#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time


SHORT_ID = "0123456789abcdef"
USER_ID = "b831381d-6324-4d53-ad4f-8cda48b30811"
SERVER_NAME = "apple.com"
SOCKS_USERNAME = "test_user"
SOCKS_PASSWORD = "test_password"


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            self.request.sendall(data)


class EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class UdpEchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        sock.sendto(data, self.client_address)


class UdpEchoServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def reserve_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def recv_exact(sock: socket.socket, size: int) -> bytes:
    output = bytearray()
    while len(output) != size:
        data = sock.recv(size - len(output))
        if not data:
            raise RuntimeError("unexpected EOF from SOCKS5 proxy")
        output.extend(data)
    return bytes(output)


def encode_socks5_address(target_host: str) -> bytes:
    try:
        return b"\x01" + socket.inet_pton(socket.AF_INET, target_host)
    except OSError:
        pass

    try:
        return b"\x04" + socket.inet_pton(socket.AF_INET6, target_host)
    except OSError:
        pass

    host = target_host.encode("ascii")
    if not host or len(host) > 255:
        raise ValueError("SOCKS5 test target domain length is invalid")
    return b"\x03" + bytes([len(host)]) + host


def open_socks5_connection(
    proxy_port: int,
    target_host: str,
    target_port: int,
    username: str | None = None,
    password: str | None = None,
) -> socket.socket:
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    try:
        sock.settimeout(10)
        if username is None or password is None:
            sock.sendall(b"\x05\x01\x00")
            if recv_exact(sock, 2) != b"\x05\x00":
                raise RuntimeError("SOCKS5 no-authentication negotiation failed")
        else:
            username_bytes = username.encode()
            password_bytes = password.encode()
            if not 0 < len(username_bytes) <= 255 or not 0 < len(password_bytes) <= 255:
                raise ValueError("SOCKS5 credential length is invalid")
            sock.sendall(b"\x05\x01\x02")
            if recv_exact(sock, 2) != b"\x05\x02":
                raise RuntimeError("SOCKS5 username and password negotiation failed")
            sock.sendall(
                b"\x01"
                + bytes([len(username_bytes)])
                + username_bytes
                + bytes([len(password_bytes)])
                + password_bytes
            )
            if recv_exact(sock, 2) != b"\x01\x00":
                raise RuntimeError("SOCKS5 username and password authentication failed")

        request = (
            b"\x05\x01\x00"
            + encode_socks5_address(target_host)
            + target_port.to_bytes(2, "big")
        )
        sock.sendall(request)
        reply_header = recv_exact(sock, 4)
        if reply_header[:3] != b"\x05\x00\x00":
            raise RuntimeError(f"SOCKS5 CONNECT failed: {reply_header.hex()}")
        if reply_header[3] == 1:
            recv_exact(sock, 6)
        elif reply_header[3] == 3:
            length = recv_exact(sock, 1)[0]
            recv_exact(sock, length + 2)
        elif reply_header[3] == 4:
            recv_exact(sock, 18)
        else:
            raise RuntimeError(f"invalid SOCKS5 reply address type: {reply_header[3]}")
        return sock
    except Exception:
        sock.close()
        raise


def socks5_echo_roundtrip(proxy_port: int, target_port: int, payload: bytes) -> None:
    with open_socks5_connection(
        proxy_port,
        "localhost",
        target_port,
        SOCKS_USERNAME,
        SOCKS_PASSWORD,
    ) as sock:
        sock.sendall(payload)
        if recv_exact(sock, len(payload)) != payload:
            raise RuntimeError("SOCKS5 echo response mismatch")


def socks5_tls_request(
    proxy_port: int,
    target_port: int,
    tls_version: ssl.TLSVersion,
    target_host: str = "localhost",
    server_hostname: str = SERVER_NAME,
) -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.minimum_version = tls_version
    context.maximum_version = tls_version
    raw = open_socks5_connection(
        proxy_port,
        target_host,
        target_port,
        SOCKS_USERNAME,
        SOCKS_PASSWORD,
    )
    with context.wrap_socket(raw, server_hostname=server_hostname) as tls:
        negotiated_version = tls.version()
        tls.sendall(f"GET / HTTP/1.0\r\nHost: {server_hostname}\r\n\r\n".encode())
        response = bytearray()
        while True:
            data = tls.recv(65536)
            if not data:
                break
            response.extend(data)
    expected_version = {
        ssl.TLSVersion.TLSv1_2: "TLSv1.2",
        ssl.TLSVersion.TLSv1_3: "TLSv1.3",
    }[tls_version]
    if negotiated_version != expected_version:
        raise RuntimeError(
            f"SOCKS5 TLS version mismatch: {negotiated_version} != {expected_version}"
        )
    if b"HTTP/1.0 200 ok" not in response:
        raise RuntimeError(
            "SOCKS5 TLS response mismatch:\n"
            + response.decode("utf-8", errors="replace")
        )


def socks5_rejects_wrong_password(proxy_port: int) -> None:
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(b"\x05\x01\x02")
        if recv_exact(sock, 2) != b"\x05\x02":
            raise RuntimeError("SOCKS5 did not select username and password authentication")
        username = SOCKS_USERNAME.encode()
        password = b"wrong_password"
        sock.sendall(
            b"\x01"
            + bytes([len(username)])
            + username
            + bytes([len(password)])
            + password
        )
        if recv_exact(sock, 2) != b"\x01\x01":
            raise RuntimeError("SOCKS5 accepted an incorrect password")


def socks5_udp_roundtrip(proxy_port: int, target_port: int, payload: bytes) -> None:
    control = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        control.settimeout(10)
        control.sendall(b"\x05\x01\x02")
        if recv_exact(control, 2) != b"\x05\x02":
            raise RuntimeError("SOCKS5 UDP authentication method negotiation failed")

        username = SOCKS_USERNAME.encode()
        password = SOCKS_PASSWORD.encode()
        control.sendall(
            b"\x01"
            + bytes([len(username)])
            + username
            + bytes([len(password)])
            + password
        )
        if recv_exact(control, 2) != b"\x01\x00":
            raise RuntimeError("SOCKS5 UDP authentication failed")

        relay.bind(("127.0.0.1", 0))
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        reply = recv_exact(control, 10)
        if reply[:4] != b"\x05\x00\x00\x01":
            raise RuntimeError(f"SOCKS5 UDP ASSOCIATE failed: {reply.hex()}")
        relay_host = socket.inet_ntoa(reply[4:8])
        relay_port = int.from_bytes(reply[8:10], "big")
        if relay_port == 0:
            raise RuntimeError("SOCKS5 UDP ASSOCIATE returned port zero")

        request = (
            b"\x00\x00\x00\x01"
            + socket.inet_aton("127.0.0.1")
            + target_port.to_bytes(2, "big")
            + payload
        )
        relay.settimeout(15)
        relay.sendto(request, (relay_host, relay_port))
        response, _ = relay.recvfrom(65535)
        if len(response) < 10 or response[:4] != b"\x00\x00\x00\x01":
            raise RuntimeError(f"invalid SOCKS5 UDP response: {response.hex()}")
        if response[4:8] != socket.inet_aton("127.0.0.1"):
            raise RuntimeError("SOCKS5 UDP response source address mismatch")
        if int.from_bytes(response[8:10], "big") != target_port:
            raise RuntimeError("SOCKS5 UDP response source port mismatch")
        if response[10:] != payload:
            raise RuntimeError("SOCKS5 UDP echo response mismatch")
    finally:
        relay.close()
        control.close()


def wait_for_listener(port: int, process: subprocess.Popen[bytes], timeout: float = 8.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"process exited before listening on {port}: {process.returncode}")
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.1)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    raise RuntimeError(f"timed out waiting for listener on port {port}")


def wait_for_text(
    path: Path,
    marker: str,
    process: subprocess.Popen[bytes],
    timeout: float = 20.0,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if marker in tail(path):
            return
        if process.poll() is not None:
            raise RuntimeError(
                f"process exited before writing {marker!r}: {process.returncode}\n{tail(path)}"
            )
        time.sleep(0.05)
    raise RuntimeError(f"timed out waiting for {marker!r}\n{tail(path)}")


def stop_process(process: subprocess.Popen[bytes] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def tail(path: Path, limit: int = 12000) -> str:
    if not path.exists():
        return ""
    data = path.read_bytes()
    return data[-limit:].decode("utf-8", errors="replace")


def generate_x25519_key_pair(xray: Path) -> tuple[str, str]:
    output = subprocess.check_output([str(xray), "x25519"], text=True)
    private_match = re.search(r"^PrivateKey:\s*(\S+)\s*$", output, re.MULTILINE)
    public_match = re.search(
        r"^(?:Password(?: \(PublicKey\))?|PublicKey):\s*(\S+)\s*$",
        output,
        re.MULTILINE,
    )
    if private_match is None or public_match is None:
        raise RuntimeError("failed to parse xray x25519 output:\n" + output)
    return private_match.group(1), public_match.group(1)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--xray", required=True, type=Path)
    parser.add_argument("--client", required=True, type=Path)
    parser.add_argument("--work-dir", required=True, type=Path)
    args = parser.parse_args()

    work_dir: Path = args.work_dir.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)
    key_path = work_dir / "decoy.key"
    cert_path = work_dir / "decoy.crt"
    config_path = work_dir / "xray.json"
    xray_log_path = work_dir / "xray.log"
    decoy_log_path = work_dir / "decoy.log"
    inner_tls_log_path = work_dir / "inner-tls.log"
    inner_tls12_log_path = work_dir / "inner-tls12.log"
    vision_socks_log_path = work_dir / "vision-socks.log"
    private_key, public_key = generate_x25519_key_pair(args.xray)

    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            f"/CN={SERVER_NAME}",
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

    decoy_port = reserve_port()
    inner_tls_port = reserve_port()
    inner_tls12_port = reserve_port()
    xray_port = reserve_port()
    vision_socks_port = reserve_port()

    def client_command(socks_port: int) -> list[str]:
        return [
            str(args.client),
            "--server",
            "127.0.0.1",
            "--port",
            str(xray_port),
            "--server_name",
            SERVER_NAME,
            "--server_public_key",
            public_key,
            "--short_id",
            SHORT_ID,
            "--uuid",
            USER_ID,
            "--socks_port",
            str(socks_port),
            "--socks_username",
            SOCKS_USERNAME,
            "--socks_password",
            SOCKS_PASSWORD,
        ]

    with EchoServer(("127.0.0.1", 0), EchoHandler) as echo_server, UdpEchoServer(("127.0.0.1", 0), UdpEchoHandler) as udp_echo_server:
        echo_port = int(echo_server.server_address[1])
        echo_thread = threading.Thread(target=echo_server.serve_forever, daemon=True)
        echo_thread.start()
        udp_echo_port = int(udp_echo_server.server_address[1])
        udp_echo_thread = threading.Thread(target=udp_echo_server.serve_forever, daemon=True)
        udp_echo_thread.start()

        config = {
            "log": {"loglevel": "debug"},
            "inbounds": [
                {
                    "listen": "127.0.0.1",
                    "port": xray_port,
                    "protocol": "vless",
                    "settings": {
                        "clients": [
                            {"id": USER_ID, "flow": "xtls-rprx-vision"},
                        ],
                        "decryption": "none",
                    },
                    "streamSettings": {
                        "network": "tcp",
                        "security": "reality",
                        "realitySettings": {
                            "dest": f"127.0.0.1:{decoy_port}",
                            "serverNames": [SERVER_NAME],
                            "privateKey": private_key,
                            "shortIds": [SHORT_ID],
                        },
                    },
                }
            ],
            "outbounds": [
                {
                    "protocol": "freedom",
                    "settings": {"finalRules": [{"action": "allow"}]},
                }
            ],
        }
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

        decoy_process: subprocess.Popen[bytes] | None = None
        inner_tls_process: subprocess.Popen[bytes] | None = None
        inner_tls12_process: subprocess.Popen[bytes] | None = None
        xray_process: subprocess.Popen[bytes] | None = None
        vision_socks_process: subprocess.Popen[bytes] | None = None
        try:
            with (
                decoy_log_path.open("wb") as decoy_log,
                inner_tls_log_path.open("wb") as inner_tls_log,
                inner_tls12_log_path.open("wb") as inner_tls12_log,
            ):
                decoy_process = subprocess.Popen(
                    [
                        str(args.xray.parent / "openssl")
                        if (args.xray.parent / "openssl").exists()
                        else "openssl",
                        "s_server",
                        "-accept",
                        f"127.0.0.1:{decoy_port}",
                        "-cert",
                        str(cert_path),
                        "-key",
                        str(key_path),
                        "-www",
                        "-tls1_3",
                    ],
                    stdout=decoy_log,
                    stderr=subprocess.STDOUT,
                )
                wait_for_listener(decoy_port, decoy_process)

                inner_tls_process = subprocess.Popen(
                    [
                        "openssl",
                        "s_server",
                        "-accept",
                        f"127.0.0.1:{inner_tls_port}",
                        "-cert",
                        str(cert_path),
                        "-key",
                        str(key_path),
                        "-www",
                        "-tls1_3",
                    ],
                    stdout=inner_tls_log,
                    stderr=subprocess.STDOUT,
                )
                wait_for_listener(inner_tls_port, inner_tls_process)

                inner_tls12_process = subprocess.Popen(
                    [
                        "openssl",
                        "s_server",
                        "-accept",
                        f"127.0.0.1:{inner_tls12_port}",
                        "-cert",
                        str(cert_path),
                        "-key",
                        str(key_path),
                        "-www",
                        "-tls1_2",
                    ],
                    stdout=inner_tls12_log,
                    stderr=subprocess.STDOUT,
                )
                wait_for_listener(inner_tls12_port, inner_tls12_process)

                with xray_log_path.open("wb") as xray_log:
                    xray_process = subprocess.Popen(
                        [str(args.xray), "run", "-config", str(config_path)],
                        stdout=xray_log,
                        stderr=subprocess.STDOUT,
                    )
                    wait_for_listener(xray_port, xray_process)

                    with vision_socks_log_path.open("wb") as vision_socks_log:
                        vision_socks_process = subprocess.Popen(
                            client_command(vision_socks_port),
                            stdout=vision_socks_log,
                            stderr=subprocess.STDOUT,
                        )
                        wait_for_text(
                            vision_socks_log_path,
                            "socks5 tcp proxy listening",
                            vision_socks_process,
                        )

                        socks5_echo_roundtrip(
                            vision_socks_port,
                            echo_port,
                            b"xray-reality-socks5-tcp-interoperability",
                        )
                        wait_for_text(
                            vision_socks_log_path,
                            "socks_1 socks5 tcp session completed",
                            vision_socks_process,
                        )

                        socks5_tls_request(
                            vision_socks_port,
                            inner_tls_port,
                            ssl.TLSVersion.TLSv1_3,
                        )
                        wait_for_text(
                            vision_socks_log_path,
                            "socks_2 socks5 tcp session completed",
                            vision_socks_process,
                        )

                        splice_count_before_tls12 = xray_log_path.read_bytes().count(
                            b"CopyRawConn splice"
                        )
                        socks5_tls_request(
                            vision_socks_port,
                            inner_tls12_port,
                            ssl.TLSVersion.TLSv1_2,
                        )
                        wait_for_text(
                            vision_socks_log_path,
                            "socks_3 socks5 tcp session completed",
                            vision_socks_process,
                        )
                        splice_count_after_tls12 = xray_log_path.read_bytes().count(
                            b"CopyRawConn splice"
                        )

                        socks5_tls_request(
                            vision_socks_port,
                            inner_tls_port,
                            ssl.TLSVersion.TLSv1_3,
                            target_host="127.0.0.1",
                            server_hostname="localhost",
                        )
                        wait_for_text(
                            vision_socks_log_path,
                            "socks_4 socks5 tcp session completed",
                            vision_socks_process,
                        )

                        socks5_rejects_wrong_password(vision_socks_port)
                        wait_for_text(
                            vision_socks_log_path,
                            "socks_5 socks5 negotiation failed",
                            vision_socks_process,
                        )

                        socks5_udp_roundtrip(
                            vision_socks_port,
                            udp_echo_port,
                            b"xray-reality-socks5-udp-interoperability",
                        )
                        wait_for_text(
                            vision_socks_log_path,
                            "socks_6 socks5 udp association completed",
                            vision_socks_process,
                        )
                        time.sleep(0.1)

                        if vision_socks_process.poll() is not None:
                            sys.stderr.write(
                                "\n--- Vision SOCKS5 log ---\n"
                                + tail(vision_socks_log_path)
                            )
                            return vision_socks_process.returncode or 1

                        socks_output = tail(vision_socks_log_path)
                        direct_markers = (
                            "socks_2 vision send padding ended with command 2",
                            "socks_2 reality send direction switched to raw",
                            "socks_2 vision receive direction entered direct mode",
                            f"socks_4 sniffed destination localhost:{inner_tls_port}",
                            "socks_4 vision send padding ended with command 2",
                            "socks_4 reality send direction switched to raw",
                            "socks_4 vision receive direction entered direct mode",
                        )
                        missing_direct = [
                            marker for marker in direct_markers if marker not in socks_output
                        ]

                        fallback_markers = (
                            "socks_1 vision send padding ended with command 1",
                            "socks_3 vision send padding ended with command 1",
                        )
                        missing_fallback = [
                            marker for marker in fallback_markers if marker not in socks_output
                        ]
                        forbidden = (
                            "socks_1 reality send direction switched to raw",
                            "socks_1 vision receive direction entered direct mode",
                            "socks_3 reality send direction switched to raw",
                            "socks_3 vision receive direction entered direct mode",
                        )
                        present_forbidden = [
                            marker for marker in forbidden if marker in socks_output
                        ]
                        udp_markers = (
                            "socks_6_udp_1 vless udp request header sent",
                            "socks_6 socks5 udp association completed",
                        )
                        missing_udp = [marker for marker in udp_markers if marker not in socks_output]
                        udp_vision_markers = [
                            line
                            for line in socks_output.splitlines()
                            if "socks_6_udp_1" in line and "vision" in line.lower()
                        ]
                        if (
                            missing_direct
                            or missing_fallback
                            or missing_udp
                            or udp_vision_markers
                            or present_forbidden
                            or splice_count_after_tls12 != splice_count_before_tls12
                        ):
                            sys.stderr.write(
                                "\nSOCKS5 assertions failed; missing direct: "
                                + ", ".join(missing_direct)
                                + "; missing fallback: "
                                + ", ".join(missing_fallback)
                                + "; missing udp: "
                                + ", ".join(missing_udp)
                                + "; udp vision markers: "
                                + ", ".join(udp_vision_markers)
                                + "; forbidden: "
                                + ", ".join(present_forbidden)
                                + "; Xray splice count: "
                                + f"{splice_count_before_tls12} -> {splice_count_after_tls12}"
                                + "\n--- Vision SOCKS5 log ---\n"
                                + socks_output
                                + "\n--- Xray log ---\n"
                                + tail(xray_log_path)
                            )
                            return 1
                        sys.stdout.write(socks_output)
        finally:
            stop_process(vision_socks_process)
            stop_process(xray_process)
            stop_process(inner_tls12_process)
            stop_process(inner_tls_process)
            stop_process(decoy_process)
            echo_server.shutdown()
            echo_thread.join(timeout=2)
            udp_echo_server.shutdown()
            udp_echo_thread.join(timeout=2)

    print(
        "Xray REALITY, VLESS Vision, VLESS UDP, SOCKS5 authentication, UDP ASSOCIATE, "
        "destination sniffing, TLS 1.2 fallback, and TLS 1.3 Direct tests passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
