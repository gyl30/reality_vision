#!/usr/bin/env python3

from __future__ import annotations

import argparse
from collections.abc import Callable
import json
import resource
from pathlib import Path
import re
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time


SHORT_ID = "01234567"
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


class HalfCloseResponseHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        request = bytearray()
        while not request.endswith(b"\n"):
            data = self.request.recv(65536)
            if not data:
                return
            request.extend(data)
        if not self.server.response_ready.wait(timeout=5):
            raise RuntimeError("timed out waiting for SOCKS5 client half-close")
        self.request.sendall(b"half-close-response:" + request)


class EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class HalfCloseServer(EchoServer):
    def __init__(self, server_address: tuple[str, int]) -> None:
        super().__init__(server_address, HalfCloseResponseHandler)
        self.response_ready = threading.Event()


class Ipv6EchoServer(EchoServer):
    address_family = socket.AF_INET6


def make_inner_tls13_server_hello() -> bytes:
    extensions = bytes.fromhex("002b0002030400330024001d0020") + bytes([0x22]) * 32
    body = (
        b"\x03\x03"
        + bytes([0x11]) * 32
        + b"\x20"
        + bytes([0x33]) * 32
        + b"\x13\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


INNER_TLS13_CLIENT_HELLO = b"\x16\x03\x01\x00\x08\x01\x00\x00\x04\x03\x03\x00\x00"
INNER_TLS13_CLIENT_RECORD = b"\x17\x03\x03\x00\x20" + bytes([0x44]) * 32
# 只发送半个 record，使 Xray 下行保持 padding（TLS record mode），随后由服务端关闭。
INNER_TLS13_PARTIAL_SERVER_RECORD = b"\x17\x03\x03\x01\x00" + bytes([0x55]) * 16


class PartialTls13Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        if recv_exact(self.request, len(INNER_TLS13_CLIENT_HELLO)) != INNER_TLS13_CLIENT_HELLO:
            raise RuntimeError("inner TLS 1.3 ClientHello mismatch")
        self.request.sendall(make_inner_tls13_server_hello())
        if recv_exact(self.request, len(INNER_TLS13_CLIENT_RECORD)) != INNER_TLS13_CLIENT_RECORD:
            raise RuntimeError("inner TLS 1.3 client record mismatch")
        self.request.sendall(INNER_TLS13_PARTIAL_SERVER_RECORD)
        self.request.shutdown(socket.SHUT_WR)
        while self.request.recv(65536):
            pass


class UdpEchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        sock.sendto(data, self.client_address)


class UdpEchoServer(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


class Ipv6UdpEchoServer(UdpEchoServer):
    address_family = socket.AF_INET6


class ServerHelloHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        header = recv_exact(self.request, 5)
        if header[:3] != b"\x16\x03\x01":
            raise RuntimeError(f"invalid REALITY test ClientHello record: {header.hex()}")
        client_hello = recv_exact(self.request, int.from_bytes(header[3:5], "big"))
        if len(client_hello) <= 39 or client_hello[0] != 0x01:
            raise RuntimeError("invalid REALITY test ClientHello handshake")
        session_id_length = client_hello[38]
        session_id = client_hello[39 : 39 + session_id_length]
        if len(session_id) != session_id_length:
            raise RuntimeError("truncated REALITY test ClientHello session ID")
        self.request.sendall(self.server.response_factory(session_id))


class ServerHelloServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        response_factory: Callable[[bytes], bytes],
    ) -> None:
        self.response_factory = response_factory
        super().__init__(server_address, ServerHelloHandler)


def reserve_listener() -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return sock
    except Exception:
        sock.close()
        raise


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


def negotiate_socks5_authentication(
    sock: socket.socket,
    username: str | None,
    password: str | None,
) -> None:
    if (username is None) != (password is None):
        raise ValueError("SOCKS5 username and password must be provided together")
    if username is None or password is None:
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise RuntimeError("SOCKS5 no-authentication negotiation failed")
        return

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


class RecordingRelay:
    def __init__(self, upstream_port: int) -> None:
        self.upstream_port = upstream_port
        self.client_bytes = bytearray()
        self.listener = socket.create_server(("127.0.0.1", 0))
        self.port = int(self.listener.getsockname()[1])
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self) -> None:
        downstream, _ = self.listener.accept()
        upstream = socket.create_connection(("127.0.0.1", self.upstream_port))

        def pump(source: socket.socket, target: socket.socket, record: bytearray | None) -> None:
            while data := source.recv(65536):
                if record is not None:
                    record.extend(data)
                target.sendall(data)
            target.shutdown(socket.SHUT_WR)

        reverse = threading.Thread(target=pump, args=(upstream, downstream, None), daemon=True)
        reverse.start()
        pump(downstream, upstream, self.client_bytes)
        reverse.join(timeout=5)
        downstream.close()
        upstream.close()

    def close(self) -> None:
        self.listener.close()
        self.thread.join(timeout=5)


def client_application_record_sizes(stream: bytes) -> list[int]:
    sizes = []
    offset = 0
    while offset + 5 <= len(stream):
        length = int.from_bytes(stream[offset + 3 : offset + 5], "big")
        if stream[offset] == 0x17:
            sizes.append(length)
        offset += 5 + length
    return sizes


def run_single_echo_client(
    client: Path,
    public_key: str,
    server_port: int,
    echo_port: int,
    log_path: Path,
) -> str:
    process: subprocess.Popen[bytes] | None = None
    try:
        with reserve_listener() as socks_reservation:
            socks_port = int(socks_reservation.getsockname()[1])
        with log_path.open("wb") as log:
            process = subprocess.Popen(
                [
                    str(client), "--server", "127.0.0.1", "--port", str(server_port),
                    "--server_name", SERVER_NAME, "--server_public_key", public_key,
                    "--short_id", SHORT_ID, "--uuid", USER_ID, "--socks_port", str(socks_port),
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            wait_for_text(log_path, "socks5 tcp proxy listening", process)
            socks5_echo_roundtrip(
                socks_port,
                echo_port,
                b"xray-reality-single-client",
                username=None,
                password=None,
            )
            wait_for_text(log_path, "socks_0_1 socks5 tcp session completed", process)
    finally:
        stop_process(process)
    return tail(log_path)


def test_vless_header_shares_first_padding_record(
    client: Path,
    public_key: str,
    xray_port: int,
    echo_port: int,
    work_dir: Path,
) -> None:
    relay = RecordingRelay(xray_port)
    try:
        output = run_single_echo_client(client, public_key, relay.port, echo_port, work_dir / "vless-header-record.log")
    finally:
        relay.close()

    # 默认 decoy 与现代站点一样优先协商 X25519MLKEM768，REALITY 会沿用 decoy 选择的 group。
    if "socks_0_1 reality key exchange X25519MLKEM768" not in output:
        raise RuntimeError("REALITY did not negotiate X25519MLKEM768:\n" + output)

    # 第一个 application_data record 是 REALITY Finished，第二个必须同时携带 VLESS 头与长 padding 首帧。
    sizes = client_application_record_sizes(bytes(relay.client_bytes))
    if len(sizes) < 2 or sizes[1] < 900:
        raise RuntimeError(f"VLESS request header is not hidden by the first Vision padding record: {sizes[:4]}")


def test_x25519_key_exchange(
    client: Path,
    public_key: str,
    xray_port: int,
    echo_port: int,
    work_dir: Path,
) -> None:
    output = run_single_echo_client(client, public_key, xray_port, echo_port, work_dir / "x25519-key-exchange.log")
    if "socks_0_1 reality key exchange X25519\n" not in output:
        raise RuntimeError("REALITY did not fall back to X25519:\n" + output)


def assert_closed_after_idle(connection: socket.socket, idle_timeout: float) -> None:
    connection.settimeout(idle_timeout + 4)
    started = time.monotonic()
    try:
        data = connection.recv(1)
    except ConnectionResetError:
        data = b""
    elapsed = time.monotonic() - started
    if data or elapsed < idle_timeout - 0.5:
        raise RuntimeError(f"idle connection was not closed by the idle timeout: {data!r} after {elapsed:.1f}s")


def test_tcp_idle_timeout(
    client: Path,
    public_key: str,
    xray_port: int,
    echo_port: int,
    work_dir: Path,
) -> None:
    log_path = work_dir / "tcp-idle-timeout.log"
    idle_timeout = 2
    process: subprocess.Popen[bytes] | None = None
    try:
        with reserve_listener() as socks_reservation:
            socks_port = int(socks_reservation.getsockname()[1])
        with log_path.open("wb") as log:
            process = subprocess.Popen(
                [
                    str(client), "--server", "127.0.0.1", "--port", str(xray_port),
                    "--server_name", SERVER_NAME, "--server_public_key", public_key,
                    "--short_id", SHORT_ID, "--uuid", USER_ID, "--socks_port", str(socks_port),
                    "--tcp_idle_timeout", str(idle_timeout),
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            wait_for_text(log_path, "socks5 tcp proxy listening", process)
            payload = b"xray-reality-idle-timeout"
            with open_socks5_connection(socks_port, "localhost", echo_port, username=None, password=None) as connection:
                connection.sendall(payload)
                if recv_exact(connection, len(payload)) != payload:
                    raise RuntimeError("idle timeout echo mismatch")
                assert_closed_after_idle(connection, idle_timeout)
    finally:
        stop_process(process)


def test_socks_listener_survives_fd_exhaustion(
    client: Path,
    public_key: str,
    xray_port: int,
    echo_port: int,
    work_dir: Path,
) -> None:
    log_path = work_dir / "fd-exhaustion.log"
    fd_limit = 32
    process: subprocess.Popen[bytes] | None = None
    idle_connections: list[socket.socket] = []
    try:
        with reserve_listener() as socks_reservation:
            socks_port = int(socks_reservation.getsockname()[1])
        with log_path.open("wb") as log:
            process = subprocess.Popen(
                [
                    str(client), "--server", "127.0.0.1", "--port", str(xray_port),
                    "--server_name", SERVER_NAME, "--server_public_key", public_key,
                    "--short_id", SHORT_ID, "--uuid", USER_ID, "--socks_port", str(socks_port),
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
                preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_NOFILE, (fd_limit, fd_limit)),
            )
            wait_for_text(log_path, "socks5 tcp proxy listening", process)
            # 空闲连接停在 SOCKS5 协商阶段并占用 fd，超过上限后 accept 返回 EMFILE。
            for _ in range(fd_limit + 8):
                idle_connections.append(socket.create_connection(("127.0.0.1", socks_port), timeout=5))
            wait_for_text(log_path, "accept failed", process)
            for connection in idle_connections:
                connection.close()
            idle_connections.clear()

            socks5_echo_roundtrip(
                socks_port,
                echo_port,
                b"xray-reality-after-fd-exhaustion",
                username=None,
                password=None,
            )
            if process.poll() is not None:
                raise RuntimeError("client exited after fd exhaustion:\n" + tail(log_path))
    finally:
        for connection in idle_connections:
            connection.close()
        stop_process(process)


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
        negotiate_socks5_authentication(sock, username, password)

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


def socks5_echo_roundtrip(
    proxy_port: int,
    target_port: int,
    payload: bytes,
    target_host: str = "localhost",
    username: str | None = SOCKS_USERNAME,
    password: str | None = SOCKS_PASSWORD,
) -> None:
    with open_socks5_connection(
        proxy_port,
        target_host,
        target_port,
        username,
        password,
    ) as sock:
        sock.sendall(payload)
        if recv_exact(sock, len(payload)) != payload:
            raise RuntimeError("SOCKS5 echo response mismatch")


def socks5_half_close_roundtrip(
    proxy_port: int,
    target_port: int,
    response_ready: threading.Event,
) -> None:
    payload = b"xray-reality-socks5-half-close-request\n"
    with open_socks5_connection(
        proxy_port,
        "localhost",
        target_port,
        username=None,
        password=None,
    ) as sock:
        sock.sendall(payload)
        sock.shutdown(socket.SHUT_WR)
        time.sleep(0.25)
        response_ready.set()
        response = bytearray()
        while True:
            data = sock.recv(65536)
            if not data:
                break
            response.extend(data)
        if response != b"half-close-response:" + payload:
            raise RuntimeError(f"SOCKS5 half-close response mismatch: {response!r}")


def socks5_close_after_direct_uplink(proxy_port: int, target_port: int) -> None:
    with open_socks5_connection(
        proxy_port,
        "localhost",
        target_port,
        username=None,
        password=None,
    ) as sock:
        sock.sendall(INNER_TLS13_CLIENT_HELLO)
        server_hello = make_inner_tls13_server_hello()
        if recv_exact(sock, len(server_hello)) != server_hello:
            raise RuntimeError("inner TLS 1.3 ServerHello mismatch")
        sock.sendall(INNER_TLS13_CLIENT_RECORD)
        if recv_exact(sock, len(INNER_TLS13_PARTIAL_SERVER_RECORD)) != INNER_TLS13_PARTIAL_SERVER_RECORD:
            raise RuntimeError("inner TLS 1.3 partial server record mismatch")
        if sock.recv(65536):
            raise RuntimeError("unexpected data after inner TLS 1.3 partial server record")
        sock.shutdown(socket.SHUT_WR)


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
        tls.unwrap()
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


def socks5_rejects_wrong_version(proxy_port: int) -> None:
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as sock:
        sock.settimeout(5)
        sock.sendall(b"\x04\x01\x00")
        try:
            if sock.recv(1):
                raise RuntimeError("SOCKS5 replied to a greeting with the wrong version")
        except ConnectionResetError:
            pass


def open_socks5_udp_association(
    proxy_port: int,
    username: str | None = SOCKS_USERNAME,
    password: str | None = SOCKS_PASSWORD,
) -> tuple[socket.socket, socket.socket, tuple[str, int]]:
    control = socket.create_connection(("127.0.0.1", proxy_port), timeout=5)
    relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        control.settimeout(10)
        negotiate_socks5_authentication(control, username, password)

        relay.bind(("127.0.0.1", 0))
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        reply = recv_exact(control, 10)
        if reply[:4] != b"\x05\x00\x00\x01":
            raise RuntimeError(f"SOCKS5 UDP ASSOCIATE failed: {reply.hex()}")
        relay_host = socket.inet_ntoa(reply[4:8])
        relay_port = int.from_bytes(reply[8:10], "big")
        if relay_port == 0:
            raise RuntimeError("SOCKS5 UDP ASSOCIATE returned port zero")
        return control, relay, (relay_host, relay_port)
    except Exception:
        relay.close()
        control.close()
        raise


def make_socks5_udp_request(
    target_host: str,
    target_port: int,
    payload: bytes,
) -> bytes:
    return (
        b"\x00\x00\x00"
        + encode_socks5_address(target_host)
        + target_port.to_bytes(2, "big")
        + payload
    )


def make_socks5_udp_domain_request(target_port: int, payload: bytes) -> bytes:
    host = b"127.0.0.1"
    return (
        b"\x00\x00\x00\x03"
        + bytes([len(host)])
        + host
        + target_port.to_bytes(2, "big")
        + payload
    )


def exchange_socks5_udp_datagram(
    relay: socket.socket,
    relay_endpoint: tuple[str, int],
    target_host: str,
    target_port: int,
    payload: bytes,
    resolved_host: str | None = None,
) -> None:
    # 回包头使用 XUDP 下行帧中的来源地址。域名目标由 Xray 决定回报原域名
    # （会话首个目标）还是解析后的 IP（之后的 Keep 帧目标）。
    relay.sendto(
        make_socks5_udp_request(target_host, target_port, payload),
        relay_endpoint,
    )
    response, _ = relay.recvfrom(65535)
    port = target_port.to_bytes(2, "big")
    headers = [b"\x00\x00\x00" + encode_socks5_address(host) + port for host in (target_host, resolved_host) if host]
    header = next((header for header in headers if response.startswith(header)), None)
    if header is None:
        raise RuntimeError(f"invalid SOCKS5 UDP response: {response.hex()}")
    if response[len(header) :] != payload:
        raise RuntimeError("SOCKS5 UDP echo response mismatch")


def socks5_udp_roundtrip(
    proxy_port: int,
    target_port: int,
    payload: bytes,
    target_host: str = "127.0.0.1",
    username: str | None = SOCKS_USERNAME,
    password: str | None = SOCKS_PASSWORD,
) -> None:
    control, relay, relay_endpoint = open_socks5_udp_association(
        proxy_port,
        username,
        password,
    )
    try:
        relay.settimeout(15)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as malformed_source:
            malformed_source.bind(("127.0.0.1", 0))
            malformed_source.sendto(b"\x00", relay_endpoint)
        time.sleep(0.05)

        exchange_socks5_udp_datagram(
            relay,
            relay_endpoint,
            target_host,
            target_port,
            payload,
        )
    finally:
        relay.close()
        control.close()


def count_text(path: Path, marker: str) -> int:
    if not path.exists():
        return 0
    return path.read_text(encoding="utf-8", errors="replace").count(marker)


def wait_for_text_count(
    path: Path,
    marker: str,
    count: int,
    process: subprocess.Popen[bytes],
    timeout: float = 20.0,
) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if count_text(path, marker) >= count:
            return
        if process.poll() is not None:
            raise RuntimeError(
                f"process exited before writing {marker!r} {count} times: "
                f"{process.returncode}\n{tail(path)}"
            )
        time.sleep(0.05)
    raise RuntimeError(
        f"timed out waiting for {marker!r} {count} times\n{tail(path)}"
    )


def socks5_udp_datagrams_share_flow(
    proxy_port: int,
    target_port: int,
    client_log_path: Path,
) -> None:
    marker = "xudp session opened"
    initial_count = count_text(client_log_path, marker)
    payloads = (
        b"a",
        bytes(range(256)),
        bytes((index * 37) % 256 for index in range(4097)),
        # Xray XUDP 客户端上限：length + 666 <= 8192。
        bytes((index * 11) % 256 for index in range(7526)),
    )
    control, relay, relay_endpoint = open_socks5_udp_association(proxy_port)
    try:
        relay.settimeout(15)
        for payload in payloads:
            exchange_socks5_udp_datagram(
                relay,
                relay_endpoint,
                "127.0.0.1",
                target_port,
                payload,
            )
        # 超限数据报被丢弃，不中断同一 XUDP 连接。
        relay.sendto(make_socks5_udp_request("127.0.0.1", target_port, b"x" * 7527), relay_endpoint)
        exchange_socks5_udp_datagram(relay, relay_endpoint, "127.0.0.1", target_port, b"after-oversized")
        flow_count = count_text(client_log_path, marker) - initial_count
        if flow_count != 1:
            raise RuntimeError(
                f"SOCKS5 UDP datagrams created {flow_count} upstream flows"
            )
    finally:
        relay.close()
        control.close()


def socks5_udp_empty_payload_is_ignored(
    proxy_port: int,
    target_port: int,
    client_log_path: Path,
) -> None:
    marker = "xudp session opened"
    initial_count = count_text(client_log_path, marker)
    control, relay, relay_endpoint = open_socks5_udp_association(proxy_port)
    try:
        relay.settimeout(5)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as empty_source:
            empty_source.bind(("127.0.0.1", 0))
            empty_source.sendto(
                make_socks5_udp_request("127.0.0.1", 443, b""),
                relay_endpoint,
            )
        time.sleep(0.05)

        exchange_socks5_udp_datagram(
            relay,
            relay_endpoint,
            "127.0.0.1",
            target_port,
            b"udp-after-empty-payload",
        )
        flow_count = count_text(client_log_path, marker) - initial_count
        if flow_count != 1:
            raise RuntimeError("SOCKS5 empty UDP payload created an upstream flow")
    finally:
        relay.close()
        control.close()


def socks5_udp_destinations_share_xudp(
    proxy_port: int,
    target_port: int,
    ipv6_target_port: int,
    client_log_path: Path,
) -> None:
    marker = "xudp session opened"
    initial_count = count_text(client_log_path, marker)
    control, relay, relay_endpoint = open_socks5_udp_association(proxy_port)
    try:
        relay.settimeout(15)
        # 同一 association 访问域名、IPv4 与 IPv6 目标，全部经同一条 XUDP 连接逐包携带目的地址。
        exchange_socks5_udp_datagram(relay, relay_endpoint, "127.0.0.1", target_port, b"udp-ipv4-destination")
        exchange_socks5_udp_datagram(relay, relay_endpoint, "::1", ipv6_target_port, b"udp-ipv6-destination")
        exchange_socks5_udp_datagram(
            relay, relay_endpoint, "localhost", target_port, b"udp-domain-destination", resolved_host="127.0.0.1"
        )
        connection_count = count_text(client_log_path, marker) - initial_count
        if connection_count != 1:
            raise RuntimeError(f"SOCKS5 UDP destinations used {connection_count} XUDP connections")
    finally:
        relay.close()
        control.close()


def socks5_udp_request_reaches_xray(
    proxy_port: int,
    target_port: int,
    payload: bytes,
    xray_log_path: Path,
    xray_process: subprocess.Popen[bytes],
) -> None:
    control, relay, relay_endpoint = open_socks5_udp_association(proxy_port)
    try:
        relay.sendto(
            make_socks5_udp_request("127.0.0.1", target_port, payload),
            relay_endpoint,
        )
        wait_for_text(
            xray_log_path,
            f"received request for udp:127.0.0.1:{target_port}",
            xray_process,
        )
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


def make_reality_inbound(port: int, decoy_port: int, private_key: str) -> dict:
    return {
        "listen": "127.0.0.1",
        "port": port,
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


def make_tls_decoy_inbound(
    port: int,
    cert_path: Path,
    key_path: Path,
    curves: list[str] | None,
) -> dict:
    tls_settings: dict = {
        "certificates": [
            {"certificateFile": str(cert_path), "keyFile": str(key_path)},
        ],
        "minVersion": "1.3",
    }
    if curves is not None:
        tls_settings["curvePreferences"] = curves
    return {
        "listen": "127.0.0.1",
        "port": port,
        "protocol": "http",
        "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": tls_settings},
    }


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


def make_p256_server_hello(session_id: bytes) -> bytes:
    extensions = bytes.fromhex("002b00020304003300450017004104") + bytes([0x22]) * 64
    body = (
        b"\x03\x03"
        + bytes([0x11]) * 32
        + bytes([len(session_id)])
        + session_id
        + b"\x13\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def make_short_session_id_server_hello(session_id: bytes) -> bytes:
    short_session_id = session_id[:-1]
    extensions = bytes.fromhex("002b0002030400330024001d0020") + bytes([0x22]) * 32
    body = (
        b"\x03\x03"
        + bytes([0x11]) * 32
        + bytes([len(short_session_id)])
        + short_session_id
        + b"\x13\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def trigger_socks5_connect_failure(proxy_port: int) -> None:
    with socket.create_connection(("127.0.0.1", proxy_port), timeout=5) as sock:
        sock.settimeout(10)
        sock.sendall(b"\x05\x01\x00")
        if recv_exact(sock, 2) != b"\x05\x00":
            raise RuntimeError("REALITY error test SOCKS5 negotiation failed")
        sock.sendall(b"\x05\x01\x00\x03\x09localhost\x00\x50")
        reply = recv_exact(sock, 4)
        if reply[0] != 0x05 or reply[1] == 0x00:
            raise RuntimeError(f"REALITY error test expected SOCKS5 failure: {reply.hex()}")


def test_server_hello_error(
    client: Path,
    public_key: str,
    work_dir: Path,
    response_factory: Callable[[bytes], bytes],
    log_name: str,
    expected_error: str,
) -> None:
    log_path = work_dir / log_name
    process: subprocess.Popen[bytes] | None = None
    with (
        ServerHelloServer(("127.0.0.1", 0), response_factory) as server,
        reserve_listener() as socks_reservation,
    ):
        socks_port = int(socks_reservation.getsockname()[1])
        server_port = int(server.server_address[1])
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            socks_reservation.close()
            with log_path.open("wb") as log:
                process = subprocess.Popen(
                    [
                        str(client), "--server", "127.0.0.1", "--port", str(server_port),
                        "--server_name", SERVER_NAME, "--server_public_key", public_key,
                        "--short_id", SHORT_ID, "--uuid", USER_ID, "--socks_port", str(socks_port),
                    ],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
                wait_for_text(log_path, "socks5 tcp proxy listening", process)
                trigger_socks5_connect_failure(socks_port)
                wait_for_text(log_path, f"socks_0_1 upstream connection failed: {expected_error}", process)
        finally:
            stop_process(process)
            server.shutdown()
            thread.join(timeout=2)


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
    inner_tls_log_path = work_dir / "inner-tls.log"
    inner_tls12_log_path = work_dir / "inner-tls12.log"
    vision_socks_log_path = work_dir / "vision-socks.log"
    vision_no_auth_socks_log_path = work_dir / "vision-no-auth-socks.log"
    private_key, public_key = generate_x25519_key_pair(args.xray)
    test_server_hello_error(
        args.client,
        public_key,
        work_dir,
        make_p256_server_hello,
        "p256-key-share.log",
        "Operation not supported",
    )
    test_server_hello_error(
        args.client,
        public_key,
        work_dir,
        make_short_session_id_server_hello,
        "short-session-id.log",
        "Bad message",
    )

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

    def client_command(
        socks_port: int,
        username: str | None = None,
        password: str | None = None,
    ) -> list[str]:
        if (username is None) != (password is None):
            raise ValueError("SOCKS5 username and password must be provided together")

        command = [
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
        ]
        if username is not None and password is not None:
            command.extend(
                [
                    "--socks_username",
                    username,
                    "--socks_password",
                    password,
                ]
            )
        return command

    with (
        EchoServer(("127.0.0.1", 0), EchoHandler) as echo_server,
        Ipv6EchoServer(("::1", 0), EchoHandler) as ipv6_echo_server,
        HalfCloseServer(("127.0.0.1", 0)) as half_close_server,
        EchoServer(("127.0.0.1", 0), PartialTls13Handler) as partial_tls13_server,
        UdpEchoServer(("127.0.0.1", 0), UdpEchoHandler) as udp_echo_server,
        Ipv6UdpEchoServer(("::1", 0), UdpEchoHandler) as ipv6_udp_echo_server,
        reserve_listener() as decoy_reservation,
        reserve_listener() as x25519_decoy_reservation,
        reserve_listener() as xray_x25519_reservation,
        reserve_listener() as inner_tls_reservation,
        reserve_listener() as inner_tls12_reservation,
        reserve_listener() as xray_reservation,
        reserve_listener() as vision_socks_reservation,
        reserve_listener() as vision_no_auth_socks_reservation,
    ):
        decoy_port = int(decoy_reservation.getsockname()[1])
        x25519_decoy_port = int(x25519_decoy_reservation.getsockname()[1])
        xray_x25519_port = int(xray_x25519_reservation.getsockname()[1])
        inner_tls_port = int(inner_tls_reservation.getsockname()[1])
        inner_tls12_port = int(inner_tls12_reservation.getsockname()[1])
        xray_port = int(xray_reservation.getsockname()[1])
        vision_socks_port = int(vision_socks_reservation.getsockname()[1])
        vision_no_auth_socks_port = int(
            vision_no_auth_socks_reservation.getsockname()[1]
        )

        echo_port = int(echo_server.server_address[1])
        echo_thread = threading.Thread(target=echo_server.serve_forever, daemon=True)
        echo_thread.start()
        ipv6_echo_port = int(ipv6_echo_server.server_address[1])
        ipv6_echo_thread = threading.Thread(
            target=ipv6_echo_server.serve_forever,
            daemon=True,
        )
        ipv6_echo_thread.start()
        half_close_port = int(half_close_server.server_address[1])
        half_close_thread = threading.Thread(
            target=half_close_server.serve_forever,
            daemon=True,
        )
        half_close_thread.start()
        partial_tls13_port = int(partial_tls13_server.server_address[1])
        partial_tls13_thread = threading.Thread(
            target=partial_tls13_server.serve_forever,
            daemon=True,
        )
        partial_tls13_thread.start()
        udp_echo_port = int(udp_echo_server.server_address[1])
        udp_echo_thread = threading.Thread(target=udp_echo_server.serve_forever, daemon=True)
        udp_echo_thread.start()
        ipv6_udp_echo_port = int(ipv6_udp_echo_server.server_address[1])
        ipv6_udp_echo_thread = threading.Thread(
            target=ipv6_udp_echo_server.serve_forever,
            daemon=True,
        )
        ipv6_udp_echo_thread.start()

        config = {
            "log": {"loglevel": "debug"},
            "inbounds": [
                make_reality_inbound(xray_port, decoy_port, private_key),
                make_reality_inbound(xray_x25519_port, x25519_decoy_port, private_key),
                # REALITY 镜像 decoy 的握手外形；Go TLS decoy 会 ack SNI，默认优先 X25519MLKEM768，与现代站点一致。
                make_tls_decoy_inbound(decoy_port, cert_path, key_path, None),
                make_tls_decoy_inbound(x25519_decoy_port, cert_path, key_path, ["X25519"]),
            ],
            "outbounds": [
                {
                    "protocol": "freedom",
                    "settings": {"finalRules": [{"action": "allow"}]},
                }
            ],
        }
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

        inner_tls_process: subprocess.Popen[bytes] | None = None
        inner_tls12_process: subprocess.Popen[bytes] | None = None
        xray_process: subprocess.Popen[bytes] | None = None
        vision_socks_process: subprocess.Popen[bytes] | None = None
        vision_no_auth_socks_process: subprocess.Popen[bytes] | None = None
        try:
            with (
                inner_tls_log_path.open("wb") as inner_tls_log,
                inner_tls12_log_path.open("wb") as inner_tls12_log,
            ):
                inner_tls_reservation.close()
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

                inner_tls12_reservation.close()
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
                    xray_reservation.close()
                    xray_x25519_reservation.close()
                    decoy_reservation.close()
                    x25519_decoy_reservation.close()
                    xray_process = subprocess.Popen(
                        [str(args.xray), "run", "-config", str(config_path)],
                        stdout=xray_log,
                        stderr=subprocess.STDOUT,
                    )
                    for port in (xray_port, xray_x25519_port, decoy_port, x25519_decoy_port):
                        wait_for_listener(port, xray_process)
                    test_vless_header_shares_first_padding_record(
                        args.client,
                        public_key,
                        xray_port,
                        echo_port,
                        work_dir,
                    )
                    test_x25519_key_exchange(
                        args.client,
                        public_key,
                        xray_x25519_port,
                        echo_port,
                        work_dir,
                    )
                    test_socks_listener_survives_fd_exhaustion(
                        args.client,
                        public_key,
                        xray_port,
                        echo_port,
                        work_dir,
                    )
                    test_tcp_idle_timeout(
                        args.client,
                        public_key,
                        xray_port,
                        echo_port,
                        work_dir,
                    )

                    with (
                        vision_socks_log_path.open("wb") as vision_socks_log,
                        vision_no_auth_socks_log_path.open("wb") as vision_no_auth_socks_log,
                    ):
                        vision_socks_reservation.close()
                        vision_socks_process = subprocess.Popen(
                            client_command(
                                vision_socks_port,
                                SOCKS_USERNAME,
                                SOCKS_PASSWORD,
                            ),
                            stdout=vision_socks_log,
                            stderr=subprocess.STDOUT,
                        )
                        wait_for_text(
                            vision_socks_log_path,
                            "socks5 tcp proxy listening",
                            vision_socks_process,
                        )

                        vision_no_auth_socks_reservation.close()
                        vision_no_auth_socks_process = subprocess.Popen(
                            client_command(vision_no_auth_socks_port),
                            stdout=vision_no_auth_socks_log,
                            stderr=subprocess.STDOUT,
                        )
                        wait_for_text(
                            vision_no_auth_socks_log_path,
                            "socks5 tcp proxy listening",
                            vision_no_auth_socks_process,
                        )

                        socks5_echo_roundtrip(
                            vision_no_auth_socks_port,
                            echo_port,
                            b"xray-reality-socks5-no-auth-interoperability",
                            username=None,
                            password=None,
                        )
                        wait_for_text(
                            vision_no_auth_socks_log_path,
                            "socks_0_1 socks5 tcp session completed",
                            vision_no_auth_socks_process,
                        )

                        socks5_echo_roundtrip(
                            vision_no_auth_socks_port,
                            ipv6_echo_port,
                            b"xray-reality-socks5-ipv6-interoperability",
                            target_host="::1",
                            username=None,
                            password=None,
                        )
                        wait_for_text(
                            vision_no_auth_socks_log_path,
                            "socks_0_2 socks5 tcp session completed",
                            vision_no_auth_socks_process,
                        )

                        socks5_half_close_roundtrip(
                            vision_no_auth_socks_port,
                            half_close_port,
                            half_close_server.response_ready,
                        )
                        wait_for_text(
                            vision_no_auth_socks_log_path,
                            "socks_0_3 socks5 tcp session completed",
                            vision_no_auth_socks_process,
                        )

                        socks5_udp_roundtrip(
                            vision_no_auth_socks_port,
                            udp_echo_port,
                            b"xray-reality-socks5-udp-no-auth-interoperability",
                            username=None,
                            password=None,
                        )
                        wait_for_text(
                            vision_no_auth_socks_log_path,
                            "socks_0_4_xudp_1 xudp session opened",
                            vision_no_auth_socks_process,
                        )
                        wait_for_text(
                            vision_no_auth_socks_log_path,
                            "socks_0_4 socks5 udp association completed",
                            vision_no_auth_socks_process,
                        )

                        # 上行进入 Direct 后 Xray 会抑制外层 close_notify，下行仍处于 TLS record mode 时只收到 TCP FIN。
                        socks5_close_after_direct_uplink(
                            vision_no_auth_socks_port,
                            partial_tls13_port,
                        )
                        wait_for_text(
                            vision_no_auth_socks_log_path,
                            "socks_0_5 socks5 tcp session completed",
                            vision_no_auth_socks_process,
                            timeout=5,
                        )
                        no_auth_output = tail(vision_no_auth_socks_log_path)
                        if (
                            "socks_0_5 vision send padding ended with command 2" not in no_auth_output
                            or "socks_0_5 vision receive direction entered direct mode" in no_auth_output
                        ):
                            raise RuntimeError(
                                "Direct uplink close test did not keep downlink in TLS record mode:\n"
                                + no_auth_output
                            )

                        socks5_echo_roundtrip(
                            vision_socks_port,
                            echo_port,
                            b"xray-reality-socks5-tcp-interoperability",
                        )
                        wait_for_text(
                            vision_socks_log_path,
                            "socks_0_1 socks5 tcp session completed",
                            vision_socks_process,
                        )

                        socks5_tls_request(
                            vision_socks_port,
                            inner_tls_port,
                            ssl.TLSVersion.TLSv1_3,
                        )
                        wait_for_text(
                            vision_socks_log_path,
                            "socks_0_2 socks5 tcp session completed",
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
                            "socks_0_3 socks5 tcp session completed",
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
                            "socks_0_4 socks5 tcp session completed",
                            vision_socks_process,
                        )

                        socks5_rejects_wrong_password(vision_socks_port)
                        wait_for_text(
                            vision_socks_log_path,
                            "socks_0_5 socks5 negotiation failed",
                            vision_socks_process,
                        )

                        socks5_udp_roundtrip(
                            vision_socks_port,
                            udp_echo_port,
                            b"xray-reality-socks5-udp-interoperability",
                        )
                        wait_for_text(
                            vision_socks_log_path,
                            "socks_0_6 socks5 udp association completed",
                            vision_socks_process,
                        )

                        socks5_udp_request_reaches_xray(
                            vision_socks_port,
                            443,
                            b"xray-reality-socks5-udp443-interoperability",
                            xray_log_path,
                            xray_process,
                        )
                        wait_for_text(
                            vision_socks_log_path,
                            "socks_0_7_xudp_1 xudp session opened",
                            vision_socks_process,
                        )
                        wait_for_text(
                            vision_socks_log_path,
                            "socks_0_7 socks5 udp association completed",
                            vision_socks_process,
                        )

                        socks5_udp_destinations_share_xudp(
                            vision_socks_port,
                            udp_echo_port,
                            ipv6_udp_echo_port,
                            vision_socks_log_path,
                        )
                        wait_for_text(
                            vision_socks_log_path,
                            "socks_0_8 socks5 udp association completed",
                            vision_socks_process,
                        )

                        socks5_udp_roundtrip(
                            vision_socks_port,
                            ipv6_udp_echo_port,
                            b"xray-reality-socks5-udp-ipv6-interoperability",
                            target_host="::1",
                        )
                        wait_for_text(
                            vision_socks_log_path,
                            "socks_0_9 socks5 udp association completed",
                            vision_socks_process,
                        )

                        socks5_udp_datagrams_share_flow(
                            vision_socks_port,
                            udp_echo_port,
                            vision_socks_log_path,
                        )
                        wait_for_text(
                            vision_socks_log_path,
                            "socks_0_10 socks5 udp association completed",
                            vision_socks_process,
                        )

                        socks5_udp_empty_payload_is_ignored(
                            vision_socks_port,
                            udp_echo_port,
                            vision_socks_log_path,
                        )
                        wait_for_text(
                            vision_socks_log_path,
                            "socks_0_11 socks5 udp association completed",
                            vision_socks_process,
                        )

                        socks5_rejects_wrong_version(vision_socks_port)
                        wait_for_text(
                            vision_socks_log_path,
                            "socks_0_12 socks5 negotiation failed: Bad message",
                            vision_socks_process,
                        )
                        time.sleep(0.1)

                        if vision_socks_process.poll() is not None:
                            sys.stderr.write(
                                "\n--- Vision SOCKS5 log ---\n"
                                + tail(vision_socks_log_path)
                            )
                            return vision_socks_process.returncode or 1
                        if vision_no_auth_socks_process.poll() is not None:
                            sys.stderr.write(
                                "\n--- Vision no-auth SOCKS5 log ---\n"
                                + tail(vision_no_auth_socks_log_path)
                            )
                            return vision_no_auth_socks_process.returncode or 1

                        socks_output = tail(vision_socks_log_path)
                        direct_markers = (
                            "socks_0_2 vision send padding ended with command 2",
                            "socks_0_2 reality send direction switched to raw",
                            "socks_0_2 vision receive direction entered direct mode",
                            f"socks_0_4 sniffed destination localhost:{inner_tls_port}",
                            "socks_0_4 vision send padding ended with command 2",
                            "socks_0_4 reality send direction switched to raw",
                            "socks_0_4 vision receive direction entered direct mode",
                        )
                        missing_direct = [
                            marker for marker in direct_markers if marker not in socks_output
                        ]

                        fallback_markers = (
                            "socks_0_1 vision send padding ended with command 1",
                            "socks_0_3 vision send padding ended with command 1",
                        )
                        missing_fallback = [
                            marker for marker in fallback_markers if marker not in socks_output
                        ]
                        forbidden = (
                            "socks_0_1 reality send direction switched to raw",
                            "socks_0_1 vision receive direction entered direct mode",
                            "socks_0_3 reality send direction switched to raw",
                            "socks_0_3 vision receive direction entered direct mode",
                        )
                        present_forbidden = [
                            marker for marker in forbidden if marker in socks_output
                        ]
                        udp_markers = (
                            "socks_0_6_xudp_1 xudp session opened",
                            "socks_0_6 socks5 udp association completed",
                            "socks_0_7_xudp_1 xudp session opened",
                            "socks_0_7 socks5 udp association completed",
                            "socks_0_8_xudp_1 xudp session opened",
                            "socks_0_8 socks5 udp association completed",
                            "socks_0_9_xudp_1 xudp session opened",
                            "socks_0_9 socks5 udp association completed",
                            "socks_0_10_xudp_1 xudp session opened",
                            "socks_0_10 socks5 udp association completed",
                            "socks_0_11_xudp_1 xudp session opened",
                            "socks_0_11 socks5 udp association completed",
                        )
                        missing_udp = [marker for marker in udp_markers if marker not in socks_output]
                        udp_vision_markers = [
                            marker
                            for marker in ("socks_0_6_xudp_1 initial empty vision padding frame sent",)
                            if marker not in socks_output
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
            stop_process(vision_no_auth_socks_process)
            stop_process(vision_socks_process)
            stop_process(xray_process)
            stop_process(inner_tls12_process)
            stop_process(inner_tls_process)
            echo_server.shutdown()
            echo_thread.join(timeout=2)
            ipv6_echo_server.shutdown()
            ipv6_echo_thread.join(timeout=2)
            half_close_server.shutdown()
            half_close_thread.join(timeout=2)
            partial_tls13_server.shutdown()
            partial_tls13_thread.join(timeout=2)
            udp_echo_server.shutdown()
            udp_echo_thread.join(timeout=2)
            ipv6_udp_echo_server.shutdown()
            ipv6_udp_echo_thread.join(timeout=2)

    print(
        "Xray REALITY, VLESS Vision, XUDP including IPv6, UDP/443, empty-payload handling, XUDP connection reuse across destinations, "
        "SOCKS5 IPv6 and TCP half-close, no-authentication and username/password authentication, "
        "UDP ASSOCIATE with both authentication modes, destination sniffing, "
        "TLS 1.2 fallback, and TLS 1.3 Direct tests passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
