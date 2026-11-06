#!/usr/bin/env python3
"""用固定 Xray 验证 SOCKS REP 与最终目标连接结果的区别。所有网络操作在私有 namespace 内。"""

import argparse
import contextlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True
import run_xray_interop as interop  # noqa: E402


class NxDomainHandler(interop.UdpEchoHandler):
    def handle(self):
        data, sock = self.request
        if len(data) >= 12:
            self.server.queries += 1
            sock.sendto(
                data[:2] + b"\x81\x83" + data[4:6] + b"\0" * 6 + data[12:],
                self.client_address,
            )


def fd_count(process):
    return len(list(Path(f"/proc/{process.pid}/fd").iterdir()))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--xray", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get("RV_SOCKS_SEMANTICS_NAMESPACE") != "1":
        os.environ["RV_SOCKS_SEMANTICS_NAMESPACE"] = "1"
        os.execvp("unshare", ["unshare", "-Urnm", sys.executable, *sys.argv])
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    args.work_dir.mkdir(parents=True, exist_ok=True)
    args.xray = args.xray.resolve()
    args.client = args.client.resolve()
    results = []
    with contextlib.ExitStack() as stack:
        echo = stack.enter_context(
            interop.EchoServer(("127.0.0.1", 0), interop.EchoHandler)
        )
        dns = stack.enter_context(
            interop.UdpEchoServer(("127.0.0.1", 0), NxDomainHandler)
        )
        dns.queries = 0
        for server in (echo, dns):
            threading.Thread(target=server.serve_forever, daemon=True).start()
            stack.callback(server.shutdown)
        refused = stack.enter_context(interop.reserve_listener())
        stalled = stack.enter_context(interop.reserve_listener())
        xray_port_socket = stack.enter_context(interop.reserve_listener())
        decoy_port_socket = stack.enter_context(interop.reserve_listener())
        xray_port, decoy_port = (
            xray_port_socket.getsockname()[1],
            decoy_port_socket.getsockname()[1],
        )
        refused_port, stalled_port = refused.getsockname()[1], stalled.getsockname()[1]
        subprocess.run(
            [
                "iptables",
                "-A",
                "INPUT",
                "-i",
                "lo",
                "-p",
                "tcp",
                "--syn",
                "--dport",
                str(stalled_port),
                "-j",
                "DROP",
            ],
            check=True,
        )
        key, cert = args.work_dir / "decoy.key", args.work_dir / "decoy.crt"
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
                str(key),
                "-out",
                str(cert),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        private, public = interop.generate_x25519_key_pair(args.xray)
        config = {
            "log": {"loglevel": "debug"},
            "dns": {
                "hosts": {"ok.test": "127.0.0.1"},
                "servers": [{"address": "127.0.0.1", "port": dns.server_address[1]}],
            },
            "inbounds": [
                interop.make_reality_inbound(xray_port, decoy_port, private),
                interop.make_tls_decoy_inbound(decoy_port, cert, key, None),
            ],
            "outbounds": [
                {
                    "protocol": "freedom",
                    "settings": {
                        "targetStrategy": "ForceIPv4",
                        "finalRules": [{"action": "allow"}],
                    },
                }
            ],
        }
        config_path = args.work_dir / "xray.json"
        config_path.write_text(json.dumps(config, indent=2))
        xray_log_path = args.work_dir / "xray.log"
        xray_log = stack.enter_context(xray_log_path.open("wb"))
        xray_port_socket.close()
        decoy_port_socket.close()
        xray = subprocess.Popen(
            [str(args.xray), "run", "-config", str(config_path)],
            stdout=xray_log,
            stderr=subprocess.STDOUT,
        )
        stack.callback(interop.stop_process, xray)
        interop.wait_for_listener(xray_port, xray)
        cases = [
            ("domain-ok", "ok.test", echo.server_address[1], 0),
            ("ip-ok", "127.0.0.1", echo.server_address[1], 0),
            ("nxdomain", "missing.invalid", echo.server_address[1], 0),
            ("refused", "127.0.0.1", refused_port, 0),
            ("stalled", "127.0.0.1", stalled_port, 0),
            ("reality-auth", "ok.test", echo.server_address[1], 1),
            ("vless-auth", "ok.test", echo.server_address[1], 0),
            ("sniff-failure", "127.0.0.1", refused_port, 0),
        ]
        for label, host, port, expected_rep in cases:
            with interop.reserve_listener() as reservation:
                socks_port = reservation.getsockname()[1]
            command = [
                str(args.client),
                "--server",
                "127.0.0.1",
                "--port",
                str(xray_port),
                "--server_name",
                interop.SERVER_NAME,
                "--server_public_key",
                public
                if label != "reality-auth"
                else "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE",
                "--short_id",
                interop.SHORT_ID,
                "--uuid",
                interop.USER_ID
                if label != "vless-auth"
                else "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "--socks_port",
                str(socks_port),
                "--tcp_idle_timeout",
                "2",
            ]
            log_path = args.work_dir / f"{label}.log"
            xray_offset = xray_log_path.stat().st_size
            with log_path.open("wb") as log:
                process = subprocess.Popen(
                    command, stdout=log, stderr=subprocess.STDOUT
                )
                try:
                    interop.wait_for_text(
                        log_path, "socks5 tcp proxy listening", process
                    )
                    before_fds = fd_count(process)
                    started = time.monotonic()
                    with socket.create_connection(
                        ("127.0.0.1", socks_port), timeout=5
                    ) as sock:
                        sock.settimeout(8)
                        sock.sendall(b"\x05\x01\x00")
                        if interop.recv_exact(sock, 2) != b"\x05\x00":
                            raise RuntimeError("unexpected SOCKS negotiation")
                        sock.sendall(
                            b"\x05\x01\x00"
                            + interop.encode_socks5_address(host)
                            + port.to_bytes(2, "big")
                        )
                        reply = interop.recv_exact(sock, 10)
                        rep_time = time.monotonic() - started
                        at_rep = log_path.read_text()
                        server_at_rep = xray_log_path.read_bytes()[xray_offset:].decode(
                            errors="replace"
                        )
                        if reply[1] != expected_rep:
                            raise RuntimeError(
                                f"{label}: REP={reply[1]}, expected {expected_rep}"
                            )
                        payload = b"semantics-exact-payload-" + bytes(range(256))
                        if label == "sniff-failure":
                            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
                            tls = context.wrap_bio(
                                incoming,
                                outgoing,
                                server_side=False,
                                server_hostname="missing.invalid",
                            )
                            try:
                                tls.do_handshake()
                            except ssl.SSLWantReadError:
                                pass
                            payload = outgoing.read()
                        terminal = "REP failure"
                        if expected_rep == 0:
                            try:
                                sock.sendall(payload)
                                if label.endswith("-ok"):
                                    if (
                                        interop.recv_exact(sock, len(payload))
                                        != payload
                                    ):
                                        raise RuntimeError(
                                            f"{label}: corrupted payload"
                                        )
                                    sock.shutdown(socket.SHUT_WR)
                                data = sock.recv(65536)
                                terminal = "EOF" if not data else "unexpected data"
                            except ConnectionResetError:
                                terminal = "RST"
                            if terminal not in ("EOF", "RST"):
                                raise RuntimeError(f"{label}: {terminal}")
                        elapsed = time.monotonic() - started
                    deadline = time.monotonic() + 5
                    while (
                        fd_count(process) != before_fds and time.monotonic() < deadline
                    ):
                        time.sleep(0.05)
                    if fd_count(process) != before_fds:
                        raise RuntimeError(f"{label}: proxy session fds remained open")
                    output = log_path.read_text()
                    server_output = xray_log_path.read_bytes()[xray_offset:].decode(
                        errors="replace"
                    )
                    if (
                        label == "sniff-failure"
                        and "sniffed destination missing.invalid:" not in output
                    ):
                        raise RuntimeError("IP CONNECT did not perform SNI sniffing")
                    if (
                        label == "reality-auth"
                        and "vless request header sent" in output
                    ):
                        raise RuntimeError(
                            "VLESS request sent after REALITY auth failure"
                        )
                    if (
                        label == "vless-auth"
                        and "invalid request user id" not in server_output
                    ):
                        raise RuntimeError("Xray did not reject the invalid UUID")
                    if label.endswith("-ok"):
                        server_result = "connected"
                        required = "connection opened to tcp:"
                    elif label in ("nxdomain", "sniff-failure"):
                        server_result = "NXDOMAIN"
                        required = "rcode: 3"
                    elif label == "refused":
                        server_result = "connection refused"
                        required = "connection refused"
                    elif label == "stalled":
                        server_result = (
                            "SYN dropped; dial pending when client idle timeout closed"
                        )
                        required = f"dialing to tcp:127.0.0.1:{port}"
                        if "connection opened to tcp:" in server_output:
                            raise RuntimeError("stalled target unexpectedly connected")
                    elif label == "vless-auth":
                        server_result = "UUID rejected"
                        required = "invalid request user id"
                    else:
                        server_result = "REALITY authentication rejected by client"
                        required = ""
                        if "upstream connection failed" not in output:
                            raise RuntimeError("REALITY failure was not reported")
                    if required not in server_output:
                        raise RuntimeError(
                            f"{label}: missing target result {required!r}"
                        )
                    states = subprocess.check_output(
                        ["ss", "-Htan", "sport", "=", f":{xray_port}"], text=True
                    )
                    row = {
                        "case": label,
                        "server_result": server_result,
                        "server_connect_logged_at_rep": "connection opened to tcp:"
                        in server_at_rep,
                        "xray_socket_states_after_client_close": [
                            line.split()[0] for line in states.splitlines()
                        ],
                        "rep": reply[1],
                        "rep_seconds": rep_time,
                        "terminal": terminal,
                        "terminal_seconds": elapsed,
                        "reality_at_rep": "handshake completed" in at_rep,
                        "vless_at_rep": "vless request header sent" in at_rep,
                        "vless_sent": "vless request header sent" in output,
                        "proxy_fds_before": before_fds,
                        "proxy_fds_after": fd_count(process),
                    }
                    (args.work_dir / f"{label}-server.log").write_text(server_output)
                    results.append(row)
                    print(json.dumps(row), flush=True)
                finally:
                    interop.stop_process(process)
        if not dns.queries:
            raise RuntimeError("controlled NXDOMAIN server was not queried")
        counters = subprocess.check_output(["iptables", "-nvL", "INPUT"], text=True)
        (args.work_dir / "stalled-syn-counters.log").write_text(counters)
        dropped = [
            line.split()[0]
            for line in counters.splitlines()
            if f"dpt:{stalled_port} " in line
        ]
        if len(dropped) != 1 or int(dropped[0]) == 0:
            raise RuntimeError("controlled unresponsive target did not drop SYNs")
    (args.work_dir / "results.json").write_text(json.dumps(results, indent=2))
    print("SOCKS CONNECT semantics: eight real Xray cases passed")


if __name__ == "__main__":
    main()
