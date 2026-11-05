#!/usr/bin/env python3
"""TUN inbound 端到端测试。

非 root 时通过 unshare 进入新的 user/net/mount namespace 运行，因此不需要真实 root。
拓扑：
  netns P：reality_vision --tun 与测试客户端；目标网段路由到 TUN。
  netns X：Xray、REALITY dest 与 echo 服务；目标地址配置在 lo 上，Xray freedom 出站本地直达。
"""

import argparse
import contextlib
import json
import os
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

NAMESPACE_MARKER = "RV_TUN_INTEROP_NAMESPACE"
TUN_NAME = "rv-tun"
SNIFF_DOMAIN = "tun-sniff.test"
OUTBOUND_MARK = 1
TCP_IDLE_TIMEOUT = 2
PROXY_VETH_ADDRESS = "10.30.0.1"
SERVER_VETH_ADDRESS = "10.30.0.2"
TARGET_V4 = "10.40.0.2"
TARGET_V6 = "fd00:40::2"
TCP_ECHO_PORT = 7001
UDP_ECHO_PORTS = (7101, 7102)
XRAY_PORT = 8443
DECOY_PORT = 8444


def run_checked(command: list[str]) -> None:
    subprocess.run(command, check=True, stdout=subprocess.DEVNULL)


def namespace_command(namespace: str, command: list[str]) -> list[str]:
    return ["ip", "netns", "exec", namespace, *command]


def run_echo_servers() -> int:
    with contextlib.ExitStack() as stack:
        servers = [
            stack.enter_context(interop.EchoServer((TARGET_V4, TCP_ECHO_PORT), interop.EchoHandler)),
            stack.enter_context(interop.Ipv6EchoServer((TARGET_V6, TCP_ECHO_PORT), interop.EchoHandler)),
        ]
        for port in UDP_ECHO_PORTS:
            servers.append(stack.enter_context(interop.UdpEchoServer((TARGET_V4, port), interop.UdpEchoHandler)))
            servers.append(stack.enter_context(interop.Ipv6UdpEchoServer((TARGET_V6, port), interop.UdpEchoHandler)))
        threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
        for thread in threads:
            thread.start()

        stopped = threading.Event()
        signal.signal(signal.SIGTERM, lambda _signum, _frame: stopped.set())
        print("tun echo servers ready", flush=True)
        stopped.wait()
        for server in servers:
            server.shutdown()
    return 0


def tcp_roundtrip(host: str, payload: bytes) -> None:
    with socket.create_connection((host, TCP_ECHO_PORT), timeout=5) as connection:
        connection.sendall(payload)
        response = interop.recv_exact(connection, len(payload))
    if response != payload:
        raise RuntimeError(f"TUN TCP echo mismatch for {host}")


def http_host_roundtrip() -> None:
    # 目标是 IP；代理应从 HTTP Host 恢复域名，由 Xray 通过 /etc/hosts 解析回同一 echo 服务。
    request = f"GET / HTTP/1.1\r\nHost: {SNIFF_DOMAIN}\r\n\r\n".encode()
    with socket.create_connection((TARGET_V4, TCP_ECHO_PORT), timeout=5) as connection:
        connection.sendall(request)
        response = interop.recv_exact(connection, len(request))
    if response != request:
        raise RuntimeError("TUN sniffed HTTP request echo mismatch")


def udp_exchange(sock: socket.socket, host: str, port: int, payload: bytes) -> None:
    sock.sendto(payload, (host, port))
    response, source = sock.recvfrom(65535)
    if source[:2] != (host, port) or response != payload:
        raise RuntimeError(f"TUN UDP echo from {source[:2]} {response!r}, expected {(host, port)} {payload!r}")


def run_client_checks() -> int:
    tcp_roundtrip(TARGET_V4, b"tun-tcp-ipv4")
    tcp_roundtrip(TARGET_V6, b"tun-tcp-ipv6")
    http_host_roundtrip()
    with socket.create_connection((TARGET_V4, TCP_ECHO_PORT), timeout=5) as connection:
        connection.sendall(b"tun-tcp-idle")
        interop.recv_exact(connection, len(b"tun-tcp-idle"))
        interop.assert_closed_after_idle(connection, TCP_IDLE_TIMEOUT)

    for family, host in ((socket.AF_INET, TARGET_V4), (socket.AF_INET6, TARGET_V6)):
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(6)
            # 同一源端口依次访问两个目标，回包必须来自各自的目标。
            udp_exchange(sock, host, UDP_ECHO_PORTS[0], b"tun-udp-first-destination")
            udp_exchange(sock, host, UDP_ECHO_PORTS[1], b"tun-udp-second-destination")
            udp_exchange(sock, host, UDP_ECHO_PORTS[0], b"tun-udp-first-again")
    print("tun client checks passed", flush=True)
    return 0


def run_reset_check() -> int:
    # 上游不可用时 lwIP 已完成三次握手，应用必须收到 RST，而不是看似正常结束的 FIN。
    # 不发送数据：lwIP 关闭仍有未读数据的连接时本身就会发 RST，服务端先发言的协议（SSH、SMTP）才会暴露问题。
    with socket.create_connection((TARGET_V4, TCP_ECHO_PORT), timeout=10) as connection:
        try:
            data = connection.recv(1)
        except ConnectionResetError:
            print("tun reset check passed", flush=True)
            return 0
    raise RuntimeError(f"expected connection reset, received {data!r}")


def launch(namespace: str, command: list[str], log_path: Path, processes: list, log_files: list) -> subprocess.Popen[bytes]:
    log_file = log_path.open("wb")
    log_files.append(log_file)
    process = subprocess.Popen(namespace_command(namespace, command), stdout=log_file, stderr=subprocess.STDOUT)
    processes.append(process)
    return process


def wait_for_tcp(namespace: str, host: str, port: int, process: subprocess.Popen[bytes], script: Path) -> None:
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"process exited before listening on {host}:{port}")
        probe = subprocess.run(
            namespace_command(namespace, [sys.executable, str(script), "probe", "--host", host, "--port", str(port)]),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if probe.returncode == 0:
            return
        time.sleep(0.05)
    raise RuntimeError(f"timed out waiting for {host}:{port}")


def run_client(namespace: str, script: Path, command: str, log_path: Path) -> None:
    with log_path.open("wb") as log:
        result = subprocess.run(
            namespace_command(namespace, [sys.executable, str(script), command]),
            stdout=log,
            stderr=subprocess.STDOUT,
            timeout=40,
        )
    if result.returncode != 0:
        raise RuntimeError(f"{command} failed\n{interop.tail(log_path)}")


def run_test(xray: Path, client: Path, work_dir: Path) -> int:
    for command in ("ip", "openssl"):
        if shutil.which(command) is None:
            raise RuntimeError(f"required command not found: {command}")
    # ip netns 需要可写的 /run/netns；只在私有 mount namespace 中覆盖 /run。
    run_checked(["mount", "-t", "tmpfs", "none", "/run"])

    script = Path(__file__).resolve()
    xray = xray.resolve()
    client = client.resolve()
    work_dir = work_dir.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)

    hosts_path = work_dir / "tun-hosts"
    hosts_path.write_text(f"127.0.0.1 localhost\n{TARGET_V4} {SNIFF_DOMAIN}\n", encoding="utf-8")
    # 私有 mount namespace 中覆盖 /etc/hosts，供 Xray freedom 解析嗅探得到的域名。
    run_checked(["mount", "--bind", str(hosts_path), "/etc/hosts"])

    proxy_namespace = "rvtunp"
    server_namespace = "rvtunx"
    processes: list[subprocess.Popen[bytes]] = []
    log_files: list = []
    proxy_log_path = work_dir / "tun-client.log"
    try:
        run_checked(["ip", "netns", "add", proxy_namespace])
        run_checked(["ip", "netns", "add", server_namespace])
        run_checked(["ip", "link", "add", "rvtp", "type", "veth", "peer", "name", "rvtx"])
        run_checked(["ip", "link", "set", "rvtp", "netns", proxy_namespace])
        run_checked(["ip", "link", "set", "rvtx", "netns", server_namespace])
        for namespace, interface, address in (
            (proxy_namespace, "rvtp", PROXY_VETH_ADDRESS),
            (server_namespace, "rvtx", SERVER_VETH_ADDRESS),
        ):
            run_checked(["ip", "-n", namespace, "link", "set", "lo", "up"])
            run_checked(["ip", "-n", namespace, "address", "add", f"{address}/24", "dev", interface])
            run_checked(["ip", "-n", namespace, "link", "set", interface, "up"])
        run_checked(["ip", "-n", server_namespace, "address", "add", f"{TARGET_V4}/32", "dev", "lo"])
        run_checked(["ip", "-n", server_namespace, "address", "add", f"{TARGET_V6}/128", "dev", "lo", "nodad"])

        echo_log_path = work_dir / "tun-echo.log"
        echo_process = launch(server_namespace, [sys.executable, str(script), "echo"], echo_log_path, processes, log_files)
        interop.wait_for_text(echo_log_path, "tun echo servers ready", echo_process)

        key_path = work_dir / "tun-decoy.key"
        cert_path = work_dir / "tun-decoy.crt"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={interop.SERVER_NAME}",
                "-days", "1", "-keyout", str(key_path), "-out", str(cert_path),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        private_key, public_key = interop.generate_x25519_key_pair(xray)
        reality_inbound = interop.make_reality_inbound(XRAY_PORT, DECOY_PORT, private_key)
        reality_inbound["listen"] = SERVER_VETH_ADDRESS
        xray_config = {
            "log": {"loglevel": "debug"},
            "inbounds": [reality_inbound, interop.make_tls_decoy_inbound(DECOY_PORT, cert_path, key_path, None)],
            "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow"}]}}],
        }
        xray_config_path = work_dir / "tun-xray.json"
        xray_config_path.write_text(json.dumps(xray_config, indent=2), encoding="utf-8")
        xray_process = launch(
            server_namespace, [str(xray), "run", "-config", str(xray_config_path)], work_dir / "tun-xray.log", processes, log_files
        )
        wait_for_tcp(server_namespace, SERVER_VETH_ADDRESS, XRAY_PORT, xray_process, script)

        proxy_process = launch(
            proxy_namespace,
            [
                str(client), "--server", SERVER_VETH_ADDRESS, "--port", str(XRAY_PORT),
                "--server_name", interop.SERVER_NAME, "--server_public_key", public_key,
                "--short_id", interop.SHORT_ID, "--uuid", interop.USER_ID,
                "--tun", "--tun_name", TUN_NAME, "--mark", str(OUTBOUND_MARK),
                "--tcp_idle_timeout", str(TCP_IDLE_TIMEOUT),
            ],
            proxy_log_path,
            processes,
            log_files,
        )
        interop.wait_for_text(proxy_log_path, f"TUN inbound {TUN_NAME} started", proxy_process)
        run_checked(["ip", "-n", proxy_namespace, "address", "add", "10.50.0.1/24", "dev", TUN_NAME])
        run_checked(["ip", "-n", proxy_namespace, "address", "add", "fd00:50::1/64", "dev", TUN_NAME, "nodad"])
        run_checked(["ip", "-n", proxy_namespace, "link", "set", TUN_NAME, "up"])
        # 全局模式：未打标记的流量都进入 TUN，REALITY 服务端地址不做排除，只靠出站 SO_MARK 绕行。
        for family in ("-4", "-6"):
            run_checked(["ip", family, "-n", proxy_namespace, "route", "add", "default", "dev", TUN_NAME, "table", "100"])
            run_checked(["ip", family, "-n", proxy_namespace, "rule", "add", "not", "fwmark", str(OUTBOUND_MARK), "lookup", "100"])

        run_client(proxy_namespace, script, "check", work_dir / "tun-check.log")
        if f"sniffed destination {SNIFF_DOMAIN}:{TCP_ECHO_PORT}" not in interop.tail(proxy_log_path, 200000):
            raise RuntimeError("TUN TCP did not sniff the HTTP Host")
        if proxy_process.poll() is not None:
            raise RuntimeError(f"reality_vision exited\n{interop.tail(proxy_log_path)}")

        interop.stop_process(xray_process)
        run_client(proxy_namespace, script, "check-reset", work_dir / "tun-check-reset.log")

        # TUN 设备被删除后读取失败，进程必须退出而不是静默丢弃全部流量。
        run_checked(["ip", "-n", proxy_namespace, "link", "delete", TUN_NAME])
        try:
            proxy_process.wait(timeout=5)
        except subprocess.TimeoutExpired as error:
            raise RuntimeError("reality_vision kept running after the TUN device was removed") from error
    except Exception:
        print(interop.tail(proxy_log_path), file=sys.stderr)
        raise
    finally:
        for process in reversed(processes):
            interop.stop_process(process)
        for log_file in log_files:
            log_file.close()

    print("TUN global routing with SO_MARK, TCP IPv4/IPv6, Host sniffing and idle timeout, UDP multi-destination, upstream reset, and device removal tests passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="command", required=True)
    run_parser = subcommands.add_parser("run")
    run_parser.add_argument("--xray", type=Path, required=True)
    run_parser.add_argument("--client", type=Path, required=True)
    run_parser.add_argument("--work-dir", type=Path, required=True)
    subcommands.add_parser("echo")
    subcommands.add_parser("check")
    subcommands.add_parser("check-reset")
    probe_parser = subcommands.add_parser("probe")
    probe_parser.add_argument("--host", required=True)
    probe_parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()

    if args.command == "run":
        if os.environ.get(NAMESPACE_MARKER) != "1":
            # 总是在新的 user/net/mount namespace 中运行：无需真实 root，也不会改动宿主的网络与 /run。
            os.environ[NAMESPACE_MARKER] = "1"
            os.execvp("unshare", ["unshare", "-Urnm", sys.executable, *sys.argv])
        return run_test(args.xray, args.client, args.work_dir)
    if args.command == "echo":
        return run_echo_servers()
    if args.command == "check":
        return run_client_checks()
    if args.command == "check-reset":
        return run_reset_check()
    with socket.create_connection((args.host, args.port), timeout=0.5):
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
