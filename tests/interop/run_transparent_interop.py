#!/usr/bin/env python3

import argparse
import contextlib
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

sys.dont_write_bytecode = True

import run_xray_interop as interop  # noqa: E402


def run_checked(command: list[str]) -> None:
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL)


def namespace_command(namespace: str, command: list[str]) -> list[str]:
    return ["ip", "netns", "exec", namespace, *command]


def allocate_port(protocol: str, dual: bool) -> int:
    socket_type = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, socket_type) as primary:
        primary.bind(("127.0.0.1", 0))
        port = int(primary.getsockname()[1])
        if not dual:
            return port
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as secondary:
            secondary.bind(("127.0.0.1", port))
        return port


def run_echo_servers(host: str, tcp_ports: list[int], udp_ports: list[int]) -> int:
    with contextlib.ExitStack() as stack:
        servers = [
            stack.enter_context(interop.EchoServer((host, port), interop.EchoHandler))
            for port in tcp_ports
        ]
        servers.extend(
            stack.enter_context(
                interop.UdpEchoServer((host, port), interop.UdpEchoHandler)
            )
            for port in udp_ports
        )
        threads = [
            threading.Thread(target=server.serve_forever, daemon=True)
            for server in servers
        ]
        for thread in threads:
            thread.start()

        stopped = threading.Event()
        signal.signal(signal.SIGTERM, lambda _signum, _frame: stopped.set())
        signal.signal(signal.SIGINT, lambda _signum, _frame: stopped.set())
        print("transparent echo servers ready", flush=True)
        stopped.wait()

        for server in servers:
            server.shutdown()
        for thread in threads:
            thread.join(timeout=2)
    return 0


def tcp_roundtrip(host: str, port: int, payload: bytes) -> None:
    with socket.create_connection((host, port), timeout=5) as connection:
        connection.sendall(payload)
        response = interop.recv_exact(connection, len(payload))
    if response != payload:
        raise RuntimeError(f"transparent TCP echo mismatch for {host}:{port}")


def run_tcp_client(host: str, redirect_port: int, tproxy_port: int) -> int:
    tcp_roundtrip(host, redirect_port, b"transparent-redirect-roundtrip")
    tcp_roundtrip(host, tproxy_port, b"transparent-tproxy-roundtrip")
    return 0


def wait_for_path(path: Path, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.05)
    raise RuntimeError(f"timed out waiting for {path}")


def udp_roundtrip(sock: socket.socket, host: str, port: int, payload: bytes) -> None:
    sock.sendto(payload, (host, port))
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline:
        response, source = sock.recvfrom(65535)
        if source == (host, port) and response == payload:
            return
    raise RuntimeError(f"transparent UDP echo mismatch for {host}:{port}")


def run_udp_client(
    host: str,
    primary_port: int,
    blocked_port: int,
    empty_sent: Path,
    empty_checked: Path,
    flow_ready: Path,
    continue_flow: Path,
) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(6)
        sock.sendto(b"", (host, primary_port))
        empty_sent.write_text("sent", encoding="utf-8")
        wait_for_path(empty_checked)

        udp_roundtrip(sock, host, primary_port, b"transparent-udp-roundtrip")
        # Xray XUDP 客户端上限：length + 666 <= 8192。
        udp_roundtrip(
            sock, host, primary_port, bytes(range(256)) * 29 + bytes(range(102))
        )
        udp_roundtrip(sock, host, 53, b"transparent-privileged-port")

        flow_ready.write_text("ready", encoding="utf-8")
        wait_for_path(continue_flow)
        # 新的 REALITY 连接已被阻断；同一客户端的新目标仍经已有 XUDP 连接收发，回包来源为该目标。
        udp_roundtrip(sock, host, blocked_port, b"new-destination-reuses-xudp")
        udp_roundtrip(sock, host, primary_port, b"existing-flow-remains-responsive")

        sock.settimeout(1)
        sock.sendto(b"x" * 7527, (host, primary_port))
        try:
            response, source = sock.recvfrom(65535)
        except TimeoutError:
            return 0
        raise RuntimeError(
            f"oversized UDP datagram unexpectedly returned {len(response)} bytes from {source}"
        )


def run_udp_worker_client(host: str, idle_seconds: float) -> int:
    targets = [
        (address, port)
        for address in (host, "10.204.0.3")
        for port in range(7000, 7016)
    ]
    report = {"sources": [], "sent": 0, "received": 0, "missing": [], "wrong": []}
    with contextlib.ExitStack() as stack:
        sockets = []
        for port in (41001, 41002):
            sock = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            sock.bind(("10.203.0.2", port))
            sock.settimeout(3)
            sockets.append(sock)
            report["sources"].append(["10.203.0.2", port])

        def exchange(sock, phase):
            sent, received, missing, wrong = 0, 0, [], []
            for offset in range(0, len(targets), 8):
                expected = {}
                for index, target in enumerate(targets[offset : offset + 8]):
                    payload = (
                        f"worker/{sock.getsockname()[1]}/{phase}/{offset + index}".encode()
                        + bytes(range(256))
                    )
                    expected[payload] = target
                    sock.sendto(payload, target)
                    sent += 1
                deadline = time.monotonic() + 3
                while expected and time.monotonic() < deadline:
                    try:
                        payload, source = sock.recvfrom(65535)
                    except TimeoutError:
                        break
                    destination = expected.pop(payload, None)
                    if destination != source:
                        wrong.append([payload[:64].hex(), source, destination])
                    else:
                        received += 1
                missing.extend(payload[:64].hex() for payload in expected)
            return sent, received, missing, wrong

        for phase in range(3):
            # 先用每个源端口的首包确定会话，再执行两个来源并发、同来源多目标交替。
            if phase == 0:
                for sock in sockets:
                    udp_roundtrip(
                        sock, host, 7000, f"warmup/{sock.getsockname()[1]}".encode()
                    )
            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(
                    executor.map(lambda sock: exchange(sock, phase), sockets)
                )
            for sent, received, missing, wrong in results:
                report["sent"] += sent
                report["received"] += received
                report["missing"].extend(missing)
                report["wrong"].extend(wrong)
        if idle_seconds:
            print(json.dumps({"before_idle": report}), flush=True)
            time.sleep(idle_seconds)
            for sock in sockets:
                udp_roundtrip(
                    sock,
                    "10.204.0.3",
                    7015,
                    f"after-idle/{sock.getsockname()[1]}".encode(),
                )
    print(json.dumps(report), flush=True)
    if report["missing"] or report["wrong"]:
        raise RuntimeError("UDP worker payload/source mismatch")
    return 0


def wait_for_namespace_listener(
    namespace: str, host: str, port: int, process: subprocess.Popen[bytes], script: Path
) -> None:
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(
                f"process exited before listening on {host}:{port}: {process.returncode}"
            )
        probe = subprocess.run(
            namespace_command(
                namespace,
                [
                    sys.executable,
                    str(script),
                    "probe",
                    "--host",
                    host,
                    "--port",
                    str(port),
                ],
            ),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if probe.returncode == 0:
            return
        time.sleep(0.05)
    raise RuntimeError(f"timed out waiting for {host}:{port}")


def namespace_port(
    namespace: str, script: Path, protocol: str = "tcp", dual: bool = False
) -> int:
    command = namespace_command(
        namespace, [sys.executable, str(script), "free-port", "--protocol", protocol]
    )
    if dual:
        command.append("--dual")
    return int(subprocess.check_output(command, text=True).strip())


def wait_for_process(
    process: subprocess.Popen[bytes], timeout: float, log_path: Path
) -> None:
    try:
        return_code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"process timed out\n{interop.tail(log_path)}") from error
    if return_code != 0:
        raise RuntimeError(
            f"process failed with {return_code}\n{interop.tail(log_path)}"
        )


def run_test(
    xray: Path,
    client: Path,
    work_dir: Path,
    workers: int = 1,
    worker_check: bool = False,
    idle_seconds: float = 0,
    dual_ingress: bool = False,
) -> int:
    if os.geteuid() != 0:
        raise RuntimeError("transparent interop test requires root")
    for command in ("ip", "iptables", "openssl"):
        if shutil.which(command) is None:
            raise RuntimeError(f"required command not found: {command}")

    script = Path(__file__).resolve()
    xray = xray.resolve()
    client = client.resolve()
    work_dir = work_dir.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)

    suffix = f"{os.getpid():x}"[-6:]
    proxy_namespace = f"rvp{suffix}"
    client_namespace = f"rvc{suffix}"
    target_namespace = f"rvt{suffix}"
    proxy_client_interface = f"rpc{suffix}"
    client_interface = f"rcc{suffix}"
    proxy_target_interface = f"rpt{suffix}"
    target_interface = f"rtt{suffix}"
    proxy_address = "10.203.0.1"
    client_address = "10.203.0.2"
    proxy_target_address = "10.204.0.1"
    target_address = "10.204.0.2"

    marker_paths = {
        name: work_dir / name
        for name in ("empty-sent", "empty-checked", "flow-ready", "continue-flow")
    }
    for path in marker_paths.values():
        path.unlink(missing_ok=True)

    processes: list[subprocess.Popen[bytes]] = []
    log_files = []
    namespaces_created: list[str] = []
    host_interfaces = [
        proxy_client_interface,
        client_interface,
        proxy_target_interface,
        target_interface,
    ]

    def launch(
        namespace: str, command: list[str], log_path: Path
    ) -> subprocess.Popen[bytes]:
        log_file = log_path.open("wb")
        log_files.append(log_file)
        process = subprocess.Popen(
            namespace_command(namespace, command),
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
        processes.append(process)
        return process

    try:
        run_checked(["ip", "netns", "add", proxy_namespace])
        namespaces_created.append(proxy_namespace)
        run_checked(["ip", "netns", "add", client_namespace])
        namespaces_created.append(client_namespace)
        run_checked(["ip", "netns", "add", target_namespace])
        namespaces_created.append(target_namespace)
        run_checked(
            [
                "ip",
                "link",
                "add",
                proxy_client_interface,
                "type",
                "veth",
                "peer",
                "name",
                client_interface,
            ]
        )
        run_checked(
            ["ip", "link", "set", proxy_client_interface, "netns", proxy_namespace]
        )
        run_checked(["ip", "link", "set", client_interface, "netns", client_namespace])
        run_checked(
            [
                "ip",
                "link",
                "add",
                proxy_target_interface,
                "type",
                "veth",
                "peer",
                "name",
                target_interface,
            ]
        )
        run_checked(
            ["ip", "link", "set", proxy_target_interface, "netns", proxy_namespace]
        )
        run_checked(["ip", "link", "set", target_interface, "netns", target_namespace])
        run_checked(
            [
                "ip",
                "-n",
                proxy_namespace,
                "address",
                "add",
                f"{proxy_address}/24",
                "dev",
                proxy_client_interface,
            ]
        )
        run_checked(
            [
                "ip",
                "-n",
                client_namespace,
                "address",
                "add",
                f"{client_address}/24",
                "dev",
                client_interface,
            ]
        )
        run_checked(
            [
                "ip",
                "-n",
                proxy_namespace,
                "address",
                "add",
                f"{proxy_target_address}/24",
                "dev",
                proxy_target_interface,
            ]
        )
        run_checked(
            [
                "ip",
                "-n",
                target_namespace,
                "address",
                "add",
                f"{target_address}/24",
                "dev",
                target_interface,
            ]
        )
        for namespace, interfaces in (
            (proxy_namespace, (proxy_client_interface, proxy_target_interface)),
            (client_namespace, (client_interface,)),
            (target_namespace, (target_interface,)),
        ):
            run_checked(["ip", "-n", namespace, "link", "set", "lo", "up"])
            for interface in interfaces:
                run_checked(["ip", "-n", namespace, "link", "set", interface, "up"])
        run_checked(
            [
                "ip",
                "-n",
                client_namespace,
                "route",
                "add",
                "10.204.0.0/24",
                "via",
                proxy_address,
            ]
        )

        run_checked(
            namespace_command(
                proxy_namespace,
                # 此拓扑的 mark 仅用于入站本地投递，不参与反向路径验证。
                [
                    "sysctl", "-q", "-w", "net.ipv4.conf.all.rp_filter=0",
                    "net.ipv4.conf.all.src_valid_mark=0",
                    f"net.ipv4.conf.{proxy_client_interface}.src_valid_mark=0",
                ],
            )
        )
        run_checked(
            ["ip", "-n", proxy_namespace, "rule", "add", "fwmark", "1", "lookup", "100"]
        )
        run_checked(
            [
                "ip",
                "-n",
                proxy_namespace,
                "route",
                "add",
                "local",
                "0.0.0.0/0",
                "dev",
                "lo",
                "table",
                "100",
            ]
        )

        allocated_ports: set[tuple[str, int]] = set()

        def unique_port(
            namespace: str, protocol: str = "tcp", dual: bool = False
        ) -> int:
            for _attempt in range(20):
                port = namespace_port(namespace, script, protocol, dual)
                key = (namespace, port)
                if key not in allocated_ports:
                    allocated_ports.add(key)
                    return port
            raise RuntimeError(f"failed to allocate a unique port in {namespace}")

        decoy_port = unique_port(proxy_namespace)
        xray_port = unique_port(proxy_namespace)
        redirect_listener_port = unique_port(proxy_namespace)
        tproxy_listener_port = unique_port(proxy_namespace, dual=True)
        redirect_target_port = unique_port(target_namespace)
        tproxy_target_port = unique_port(target_namespace)
        udp_target_port = unique_port(target_namespace, protocol="udp")
        blocked_udp_target_port = unique_port(target_namespace, protocol="udp")

        iptables = namespace_command(proxy_namespace, ["iptables", "-w"])
        run_checked(
            iptables
            + [
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-i",
                proxy_client_interface,
                "-p",
                "tcp",
                "--dport",
                str(redirect_target_port),
                "-j",
                "REDIRECT",
                "--to-ports",
                str(redirect_listener_port),
            ]
        )
        for protocol, destination_port in (
            ("tcp", tproxy_target_port),
            ("udp", udp_target_port),
            ("udp", blocked_udp_target_port),
            ("udp", 53),
        ):
            run_checked(
                iptables
                + [
                    "-t",
                    "mangle",
                    "-A",
                    "PREROUTING",
                    "-i",
                    proxy_client_interface,
                    "-p",
                    protocol,
                    "--dport",
                    str(destination_port),
                    "-j",
                    "TPROXY",
                    "--on-port",
                    str(tproxy_listener_port),
                    "--tproxy-mark",
                    "1/1",
                ]
            )

        echo_log_path = work_dir / "transparent-echo.log"
        echo_process = launch(
            target_namespace,
            [
                sys.executable,
                str(script),
                "echo",
                "--host",
                target_address,
                "--tcp-port",
                str(redirect_target_port),
                "--tcp-port",
                str(tproxy_target_port),
                "--udp-port",
                str(udp_target_port),
                "--udp-port",
                str(blocked_udp_target_port),
                "--udp-port",
                "53",
            ],
            echo_log_path,
        )
        interop.wait_for_text(
            echo_log_path, "transparent echo servers ready", echo_process
        )

        key_path = work_dir / "transparent-decoy.key"
        cert_path = work_dir / "transparent-decoy.crt"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                f"/CN={interop.SERVER_NAME}",
                "-days",
                "1",
                "-keyout",
                str(key_path),
                "-out",
                str(cert_path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        private_key, public_key = interop.generate_x25519_key_pair(xray)

        xray_config_path = work_dir / "transparent-xray.json"
        xray_config = {
            "log": {"loglevel": "debug"},
            "inbounds": [
                interop.make_reality_inbound(xray_port, decoy_port, private_key),
                interop.make_tls_decoy_inbound(decoy_port, cert_path, key_path, None),
            ],
            "outbounds": [
                {
                    "protocol": "freedom",
                    "settings": {"finalRules": [{"action": "allow"}]},
                }
            ],
        }
        xray_config_path.write_text(json.dumps(xray_config, indent=2), encoding="utf-8")
        xray_log_path = work_dir / "transparent-xray.log"
        xray_process = launch(
            proxy_namespace,
            [str(xray), "run", "-config", str(xray_config_path)],
            xray_log_path,
        )
        wait_for_namespace_listener(
            proxy_namespace, "127.0.0.1", xray_port, xray_process, script
        )

        proxy_log_path = work_dir / "transparent-client.log"
        proxy_process = launch(
            proxy_namespace,
            [
                str(client),
                "--server",
                "127.0.0.1",
                "--port",
                str(xray_port),
                "--server_name",
                interop.SERVER_NAME,
                "--server_public_key",
                public_key,
                "--short_id",
                interop.SHORT_ID,
                "--uuid",
                interop.USER_ID,
                "--redirect_port",
                str(redirect_listener_port),
                "--tproxy_port",
                str(tproxy_listener_port),
                "--workers",
                str(workers),
            ],
            proxy_log_path,
        )
        for marker in (
            "redirect tcp proxy listening",
            "tproxy tcp proxy listening",
            "tproxy udp proxy listening",
        ):
            interop.wait_for_text(proxy_log_path, marker, proxy_process)

        tcp_client_log_path = work_dir / "transparent-tcp-client.log"
        tcp_client = launch(
            client_namespace,
            [
                sys.executable,
                str(script),
                "tcp-client",
                "--host",
                target_address,
                "--redirect-port",
                str(redirect_target_port),
                "--tproxy-port",
                str(tproxy_target_port),
            ],
            tcp_client_log_path,
        )
        wait_for_process(tcp_client, 15, tcp_client_log_path)

        if worker_check:
            run_checked(
                [
                    "ip",
                    "-n",
                    target_namespace,
                    "address",
                    "add",
                    "10.204.0.3/32",
                    "dev",
                    "lo",
                ]
            )
            run_checked(
                iptables
                + [
                    "-t",
                    "mangle",
                    "-A",
                    "PREROUTING",
                    "-i",
                    proxy_client_interface,
                    "-p",
                    "udp",
                    "--dport",
                    "7000:7015",
                    "-j",
                    "TPROXY",
                    "--on-port",
                    str(tproxy_listener_port),
                    "--tproxy-mark",
                    "1/1",
                ]
            )
            for address in (target_address, "10.204.0.3"):
                worker_echo_log = work_dir / f"worker-echo-{address}.log"
                worker_echo = launch(
                    target_namespace,
                    [sys.executable, str(script), "echo", "--host", address]
                    + [
                        argument
                        for port in range(7000, 7016)
                        for argument in ("--udp-port", str(port))
                    ],
                    worker_echo_log,
                )
                interop.wait_for_text(
                    worker_echo_log, "transparent echo servers ready", worker_echo
                )
            if dual_ingress:
                # 同一个绑定源 IP:Port 经两个入口接入，第二个目标经另一条 veth 到同一代理。
                run_checked(
                    [
                        "ip",
                        "-n",
                        proxy_namespace,
                        "link",
                        "add",
                        "rvp2",
                        "type",
                        "veth",
                        "peer",
                        "name",
                        "rvc2",
                    ]
                )
                run_checked(
                    [
                        "ip",
                        "-n",
                        proxy_namespace,
                        "link",
                        "set",
                        "rvc2",
                        "netns",
                        client_namespace,
                    ]
                )
                for namespace, interface, address in (
                    (proxy_namespace, "rvp2", "10.205.0.1"),
                    (client_namespace, "rvc2", "10.205.0.2"),
                ):
                    run_checked(
                        [
                            "ip",
                            "-n",
                            namespace,
                            "address",
                            "add",
                            f"{address}/24",
                            "dev",
                            interface,
                        ]
                    )
                    run_checked(["ip", "-n", namespace, "link", "set", interface, "up"])
                run_checked(
                    [
                        "ip",
                        "-n",
                        client_namespace,
                        "route",
                        "add",
                        "10.204.0.3/32",
                        "via",
                        "10.205.0.1",
                    ]
                )
                run_checked(
                    namespace_command(
                        proxy_namespace,
                        ["sysctl", "-q", "-w", "net.ipv4.conf.rvp2.src_valid_mark=0"],
                    )
                )
                run_checked(
                    iptables
                    + [
                        "-t",
                        "mangle",
                        "-A",
                        "PREROUTING",
                        "-i",
                        "rvp2",
                        "-p",
                        "udp",
                        "--dport",
                        "7000:7015",
                        "-j",
                        "TPROXY",
                        "--on-port",
                        str(tproxy_listener_port),
                        "--tproxy-mark",
                        "1/1",
                    ]
                )
            worker_log = work_dir / "worker-client.log"
            worker_client = launch(
                client_namespace,
                [
                    sys.executable,
                    str(script),
                    "udp-worker-client",
                    "--host",
                    target_address,
                    "--idle-seconds",
                    str(idle_seconds),
                ],
                worker_log,
            )
            idle_closed = None
            if idle_seconds:
                interop.wait_for_text(
                    worker_log, '"before_idle"', worker_client, timeout=80
                )
                before_idle = re.findall(
                    r"(udp_tproxy_\d+_\d+) transparent udp from (10\.203\.0\.2:4100[12])",
                    proxy_log_path.read_text(),
                )
                if len(before_idle) != 2 or len({peer for _, peer in before_idle}) != 2:
                    raise RuntimeError(
                        f"multiple XUDP sessions before idle: {before_idle}"
                    )
                deadline = time.monotonic() + 124
                while time.monotonic() < deadline:
                    connections = subprocess.check_output(
                        namespace_command(
                            proxy_namespace,
                            [
                                "ss",
                                "-Htn",
                                "state",
                                "established",
                                "dport",
                                "=",
                                f":{xray_port}",
                            ],
                        ),
                        text=True,
                    )
                    if not connections.strip():
                        idle_closed = True
                        break
                    time.sleep(1)
                if not idle_closed:
                    raise RuntimeError(
                        "idle UDP upstream TCP connections remained open"
                    )
            result = worker_client.wait(timeout=idle_seconds + 90)
            output = proxy_log_path.read_text()
            sessions = re.findall(
                r"(udp_tproxy_\d+_\d+) transparent udp from (10\.203\.0\.2:4100[12])",
                output,
            )
            ids = re.findall(
                r"XUDP (?:new|hit) (\[[0-9 ]+\])", xray_log_path.read_text()
            )
            summary = {
                "workers": workers,
                "sessions": sessions,
                "global_ids": ids,
                "client_exit": result,
                "idle_connections_closed": idle_closed,
            }
            (work_dir / "worker-summary.json").write_text(json.dumps(summary, indent=2))
            print(json.dumps(summary), flush=True)
            wait_for_process(worker_client, 1, worker_log)
            expected = 2 if not idle_seconds else 4
            if len(sessions) != expected or len(set(ids)) != 2:
                raise RuntimeError(
                    f"expected {expected} sessions and two GlobalIDs: {summary}"
                )
            for source in ("10.203.0.2:41001", "10.203.0.2:41002"):
                if sum(peer == source for _, peer in sessions) != expected // 2:
                    raise RuntimeError(
                        f"unexpected session reuse for {source}: {summary}"
                    )

        flows_before_empty = proxy_log_path.read_text().count(" transparent udp from ")
        udp_client_log_path = work_dir / "transparent-udp-client.log"
        udp_client = launch(
            client_namespace,
            [
                sys.executable,
                str(script),
                "udp-client",
                "--host",
                target_address,
                "--primary-port",
                str(udp_target_port),
                "--blocked-port",
                str(blocked_udp_target_port),
                "--empty-sent",
                str(marker_paths["empty-sent"]),
                "--empty-checked",
                str(marker_paths["empty-checked"]),
                "--flow-ready",
                str(marker_paths["flow-ready"]),
                "--continue-flow",
                str(marker_paths["continue-flow"]),
            ],
            udp_client_log_path,
        )
        wait_for_path(marker_paths["empty-sent"])
        time.sleep(1)
        if (
            proxy_log_path.read_text().count(" transparent udp from ")
            != flows_before_empty
        ):
            raise RuntimeError("empty TPROXY UDP datagram created a flow")
        marker_paths["empty-checked"].write_text("checked", encoding="utf-8")

        wait_for_path(marker_paths["flow-ready"])
        run_checked(
            iptables
            + [
                "-t",
                "filter",
                "-A",
                "OUTPUT",
                "-p",
                "tcp",
                "-d",
                "127.0.0.1",
                "--dport",
                str(xray_port),
                "--syn",
                "-j",
                "DROP",
            ]
        )
        marker_paths["continue-flow"].write_text("continue", encoding="utf-8")
        wait_for_process(udp_client, 15, udp_client_log_path)

        proxy_output = interop.tail(proxy_log_path)
        for marker in (
            r"redirect_\d+_\d+ transparent connect",
            r"tcp_tproxy_\d+_\d+ transparent connect",
            r"transparent udp",
        ):
            if not re.search(marker, proxy_output):
                raise RuntimeError(
                    f"missing transparent marker {marker!r}\n{proxy_output}"
                )
    finally:
        for process in reversed(processes):
            interop.stop_process(process)
        for log_file in log_files:
            log_file.close()
        for namespace in reversed(namespaces_created):
            subprocess.run(
                ["ip", "netns", "delete", namespace],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        for interface in host_interfaces:
            subprocess.run(
                ["ip", "link", "delete", interface],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

    print(
        "TCP REDIRECT, TCP/UDP TPROXY, UDP boundaries, and UDP flow isolation tests passed"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--xray", required=True, type=Path)
    run_parser.add_argument("--client", required=True, type=Path)
    run_parser.add_argument("--work-dir", required=True, type=Path)
    run_parser.add_argument("--workers", type=int, choices=(1, 2, 4), default=1)
    run_parser.add_argument("--udp-worker-check", action="store_true")
    run_parser.add_argument("--dual-ingress", action="store_true")
    run_parser.add_argument("--idle-seconds", type=float, default=0)
    worker_parser = subparsers.add_parser("udp-worker-client")
    worker_parser.add_argument("--host", required=True)
    worker_parser.add_argument("--idle-seconds", type=float, default=0)

    port_parser = subparsers.add_parser("free-port")
    port_parser.add_argument("--protocol", choices=("tcp", "udp"), required=True)
    port_parser.add_argument("--dual", action="store_true")

    echo_parser = subparsers.add_parser("echo")
    echo_parser.add_argument("--host", required=True)
    echo_parser.add_argument("--tcp-port", action="append", default=[], type=int)
    echo_parser.add_argument("--udp-port", action="append", default=[], type=int)

    probe_parser = subparsers.add_parser("probe")
    probe_parser.add_argument("--host", required=True)
    probe_parser.add_argument("--port", required=True, type=int)

    tcp_parser = subparsers.add_parser("tcp-client")
    tcp_parser.add_argument("--host", required=True)
    tcp_parser.add_argument("--redirect-port", required=True, type=int)
    tcp_parser.add_argument("--tproxy-port", required=True, type=int)

    udp_parser = subparsers.add_parser("udp-client")
    udp_parser.add_argument("--host", required=True)
    udp_parser.add_argument("--primary-port", required=True, type=int)
    udp_parser.add_argument("--blocked-port", required=True, type=int)
    udp_parser.add_argument("--empty-sent", required=True, type=Path)
    udp_parser.add_argument("--empty-checked", required=True, type=Path)
    udp_parser.add_argument("--flow-ready", required=True, type=Path)
    udp_parser.add_argument("--continue-flow", required=True, type=Path)

    args = parser.parse_args()
    if args.command == "run":
        return run_test(
            args.xray,
            args.client,
            args.work_dir,
            args.workers,
            args.udp_worker_check,
            args.idle_seconds,
            args.dual_ingress,
        )
    if args.command == "udp-worker-client":
        return run_udp_worker_client(args.host, args.idle_seconds)
    if args.command == "free-port":
        print(allocate_port(args.protocol, args.dual))
        return 0
    if args.command == "echo":
        return run_echo_servers(args.host, args.tcp_port, args.udp_port)
    if args.command == "probe":
        with socket.create_connection((args.host, args.port), timeout=0.5):
            return 0
    if args.command == "tcp-client":
        return run_tcp_client(args.host, args.redirect_port, args.tproxy_port)
    return run_udp_client(
        args.host,
        args.primary_port,
        args.blocked_port,
        args.empty_sent,
        args.empty_checked,
        args.flow_ready,
        args.continue_flow,
    )


if __name__ == "__main__":
    raise SystemExit(main())
