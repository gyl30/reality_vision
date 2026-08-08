# reality-vision-cpp

一个以 C++23 协程为边界的客户端实现，当前包含：

- Boost.Asio `tcp_byte_stream`；
- REALITY 客户端握手与受限 TLS 1.3 record layer；
- VLESS TCP request（固定 `xtls-rprx-vision` addon）与 VLESS UDP datagram framing（空 flow，不经过 Vision）；
- XTLS-Vision padding，以及收、发方向独立切换的 Direct splice；
- 本地 SOCKS5 `CONNECT` / `UDP ASSOCIATE` 代理（支持无认证或用户名密码认证，以及域名、IPv4 和 IPv6）；
- Linux IPv4 TCP REDIRECT，以及 TCP/UDP TPROXY 透明入站；
- IP 目标的轻量 destination sniffer（TLS SNI / HTTP Host）；
- spdlog 会话日志；
- 基于真实 Xray 进程的端到端互通测试。

网络层不会把数据主动推给协议层。每一层都持有下层 stream；上层需要数据时才
`co_await read(..., ec)`，写入则使用 `co_await write(..., ec)`。
预期的网络、协议和认证失败通过 `boost::system::error_code&` 返回，不依赖异常传播。

所有 C++ 源文件和头文件均平铺在 `src/`。加密实现位于 `src/crypto.cpp`，头文件不暴露任何 BoringSSL 类型；工程没有使用
`SSL*`、`boost::asio::ssl` 或由 TLS 库控制的网络缓冲区。

## 当前互通基线

已经以自动化端到端测试验证：

- Xray-core `5ca6f4b7d4dc20a881d4330e498892697627ec0c`（v26.7.28）；
- REALITY + VLESS + XTLS-Vision 普通 padding 帧双向传输；
- 内层 OpenSSL TLS 1.3 会话触发 Vision `command=2`；
- 外层 REALITY 的 TX/RX 分别从 TLS record mode 切换到 raw mode；
- splice 后的完整 HTTP 响应。

固定 ClientHello profile 来自 uTLS `HelloFirefox_120`，参考提交为
`aa6edf4b11af`。当前不是泛化的指纹引擎；profile 被明确建模成
`client_hello_profile::firefox_120`，方便以后增加更多实现。

## 支持范围

- REALITY client；
- TLS 1.3、X25519；
- `TLS_AES_128_GCM_SHA256`；
- `TLS_AES_256_GCM_SHA384`；
- `TLS_CHACHA20_POLY1305_SHA256`；
- REALITY Ed25519 leaf certificate、HMAC-SHA512、CertificateVerify 和 Finished 校验；
- VLESS TCP 使用固定 `xtls-rprx-vision`；VLESS UDP 使用 command `0x02`、空 flow 和 2-byte big-endian datagram length；
- SOCKS5 `CONNECT` / `UDP ASSOCIATE` 与 RFC 1929 用户名密码认证；UDP association 可按目标复用独立 VLESS UDP flow；
- Vision 对内层 TLS 1.3 `0x1301..0x1304` 的 Direct 判定；
- 非 TLS TCP 和内层 TLS 1.2 通过 Vision `command=1` 回退并继续透明传输；
- IPv4、IPv6 和 domain 类型的 VLESS 目标地址；
- SOCKS 或透明入站目标为 IP 时可从 TLS ClientHello SNI 或 HTTP/1.x Host 恢复域名，探测失败保持原目标；
- Linux IPv4 TCP REDIRECT 使用 `SO_ORIGINAL_DST` 恢复 NAT 前目标；TPROXY TCP/UDP 使用 `IP_TRANSPARENT`，UDP 通过 `IP_RECVORIGDSTADDR` 获取每个 datagram 的原目标。

当前有意不支持：HelloRetryRequest、0-RTT、session resumption、KeyUpdate、
X25519MLKEM768、ML-DSA 附加校验和 Xray 的 spider fallback。REALITY 身份校验失败时
会直接失败，不会把连接当作普通网站 TLS 会话继续使用。

SOCKS5 当前只监听本机回环地址；不支持 `BIND`，支持 `UDP ASSOCIATE` 但不支持 SOCKS5 UDP fragmentation (`FRAG != 0`)。
透明入站当前支持 Linux IPv4 TCP REDIRECT、TCP TPROXY 和 UDP TPROXY；不实现通用 UDP REDIRECT。IPv6 transparent 和 DNS 专用劫持留到后续阶段。UDP/443 可按普通 UDP 转发，但当前不解析或 sniff QUIC。

## 目录与依赖关系

```text
src/
  config.hpp / config.cpp       命令行配置结构、解析与校验
  main.cpp                      程序入口和连接运行流程
  base64.* / hex.*              文本编解码
  reality_*                     REALITY 协议实现
  vless_*                       VLESS TCP / UDP 协议实现
  vision_*                      XTLS-Vision 实现
  socks5_protocol.*             SOCKS5 协议实现
  sniffer.*                     TLS SNI / HTTP Host 目标探测
  transparent.*                 Linux REDIRECT / TPROXY socket helper
  udp_proxy.*                    SOCKS5 / TPROXY UDP session 与 relay
  tcp_byte_stream.*             TCP 字节流
  crypto.*                      BoringSSL 封装
  protocol_tests.*              内置协议自测

tests/interop/                  Xray 互通测试脚本
docs/                           架构与兼容性说明
```

```text
TCP:
vision_stream -> vless_stream -> reality_stream -> tcp_byte_stream -> Boost.Asio TCP
                              |
                              +-------------> crypto wrapper -> BoringSSL

SOCKS5 CONNECT / REDIRECT / TPROXY TCP
    -> optional sniffer -> VLESS TCP -> Vision -> REALITY

UDP:
SOCKS5 UDP ASSOCIATE / TPROXY UDP
    -> UDP session -> VLESS UDP (empty flow) -> REALITY -> TCP transport

UDP never enters vision_stream.

所有 .cpp 最终直接编入 reality_vision 可执行文件，不生成中间静态库。
```

更完整的数据结构、状态机和协程协作约定见
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。固定版本和协议取舍见
[`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md)。

## 构建

依赖：

- CMake 3.24+；
- C++23 编译器；
- 提供 `Boost::headers`、`Boost::system` 与 `Boost::program_options` 的 Boost CMake package；
- 提供 `spdlog::spdlog` 的 spdlog CMake package；
- BoringSSL 安装生成的 `OpenSSLConfig.cmake`。

工程不下载、不编译第三方依赖。直接使用本机已经安装的包：

```sh
cmake -S . -B build \
  -DOpenSSL_DIR=/path/to/boringssl/lib/cmake/OpenSSL \
  -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j12
ctest --test-dir build --output-on-failure
```

CMake 只创建一个 `reality_vision` executable，所有实现源文件直接编入该目标。它直接链接：

- `Boost::headers`；
- `spdlog::spdlog`；
- `OpenSSL::SSL`；
- `OpenSSL::Crypto`；
- `Threads::Threads`；
- `Boost::program_options`；
- `Boost::system`。

`OpenSSL_DIR` 必须指向 BoringSSL 安装生成的 package；普通 OpenSSL 不提供实现所用的
`EVP_AEAD` 等接口。

主要 CMake 开关：

- `RV_BUILD_TESTS=ON|OFF`；
- `OpenSSL_DIR=/path/to/boringssl/lib/cmake/OpenSSL`；
- `RV_XRAY_EXECUTABLE=/path/to/xray`：启用真实 Xray 互通测试。

协议自测已经编入同一个二进制，也可以直接运行 `./build/reality_vision --self_test`。
Xray 互通测试覆盖 SOCKS5 非 TLS、TLS 1.2 fallback、TLS 1.3 Direct、IP 目标 TLS SNI sniff、Vision framing，
并验证 SOCKS5 正确/错误密码、`UDP ASSOCIATE -> VLESS UDP -> UDP echo`、SOCKS5 UDP 地址类型 flow 隔离以及 UDP/443 request；还需要 Python 3 和系统的 OpenSSL 命令行工具。

## 作为 SOCKS5 TCP / UDP 代理运行

启动 Xray 服务端后运行：

```sh
./build/reality_vision \
  --server 127.0.0.1 --port 8443 \
  --server_name apple.com \
  --server_public_key 'uL4rG3uX_6B359RLXYFNTmSWnrBSLVv1PIG6NUWjMVk' \
  --short_id 01234567 \
  --uuid b831381d-6324-4d53-ad4f-8cda48b30811 \
  --socks_port 1080 \
  --socks_username test_user \
  --socks_password test_password
```

`--short_id` 与 Xray 的 REALITY 配置保持一致：允许 0～16 个十六进制字符，非空时必须为偶数长度；不足 8 字节的部分在尾部补 0。

这条命令监听 `127.0.0.1:1080`。使用 `socks5h` 时 SOCKS 请求直接携带域名，不需要额外探测：

```sh
curl --proxy socks5h://test_user:test_password@127.0.0.1:1080 https://apple.com/ -v
```

如果 SOCKS 请求携带 IPv4/IPv6，代理会在 REALITY 建立后先返回 SOCKS success，再最多缓存客户端首个 16 KiB / 200 ms。
若从 TLS ClientHello SNI 或 HTTP/1.x `Host` 找到域名，则 VLESS 使用该域名和原端口；
否则保持原 IP。缓存字节随后原样写入 Vision。

验证非 TLS 和 TLS 1.2 fallback：

```sh
curl --proxy socks5h://test_user:test_password@127.0.0.1:1080 http://example.com/ -v
curl --proxy socks5h://test_user:test_password@127.0.0.1:1080 \
  --tlsv1.2 --tls-max 1.2 --http1.1 \
  https://apple.com/ -v
```

这两种连接都应出现 `vision send padding ended with command 1`，且不应出现 raw switch。

不传 `--socks_username` 和 `--socks_password` 时使用无认证模式；两个参数必须同时提供，
每项长度为 1 到 255 bytes。日志不会输出凭据。

该模式会持续 accept。每个 SOCKS5 TCP CONNECT 请求独立创建
`tcp_byte_stream -> reality_stream -> vless_stream -> vision_stream`。客户端或远端 EOF 会按
TCP half-close 传播，另一方向继续排空后再释放连接。

`UDP ASSOCIATE` 使用同一个 `--socks_port`：TCP 控制连接建立 association，服务端返回一个回环 UDP relay endpoint。
SOCKS5 UDP header 中的目标地址/端口决定远端 VLESS UDP flow；同一 association 对同一地址类型、目标地址和端口复用 flow，不同目标各自建立
`reality_stream -> vless_udp_stream`。SOCKS5 UDP flow 与 TPROXY UDP flow 都在 120 秒无活动后回收。UDP flow 的 VLESS addon 长度为 0，不创建 `vision_stream`，datagram 在 VLESS body 中按
`uint16_be length + payload` 保持边界。SOCKS5 `FRAG != 0` 当前拒绝。UDP/443 与其他 UDP 使用相同的 VLESS UDP + REALITY 路径，不经过 Vision。

## 作为 Linux TCP / UDP 透明代理运行

`--redirect_port` 和 `--tproxy_port` 都是可选 listener；`--socks_port` 也不再强制要求。三个端口至少配置一个，
因此可以只运行透明代理，也可以同时保留 SOCKS5。REDIRECT 当前只接受 IPv4 TCP；配置 `--tproxy_port` 时，同一数值端口会同时监听 IPv4 TCP 和 UDP。

REDIRECT 是推荐主路径。程序对 accepted socket 使用 `SO_ORIGINAL_DST` 恢复 NAT 前的目标地址：

```sh
./build/reality_vision \
  --server 127.0.0.1 --port 8443 \
  --server_name apple.com \
  --server_public_key 'uL4rG3uX_6B359RLXYFNTmSWnrBSLVv1PIG6NUWjMVk' \
  --short_id 01234567 \
  --uuid b831381d-6324-4d53-ad4f-8cda48b30811 \
  --redirect_port 12346
```

REDIRECT 的 netfilter 规则需要由部署脚本创建。以专用运行用户 `rvproxy` 为例，本机 OUTPUT 至少要先排除代理进程
自身和不应代理的本地目标，再执行 REDIRECT：

```sh
iptables -t nat -N RV_REDIRECT
iptables -t nat -A RV_REDIRECT -d 127.0.0.0/8 -j RETURN
iptables -t nat -A RV_REDIRECT -p tcp -j REDIRECT --to-ports 12346

iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner rvproxy -j RETURN
iptables -t nat -A OUTPUT -p tcp -j RV_REDIRECT
```

实际部署还应在进入 `RV_REDIRECT` 前排除 REALITY 服务端地址、内网/Tailscale 等直连目标，否则程序连接 REALITY
服务端时可能再次进入自身形成回环。Docker/KVM 转发流量通常从 `nat PREROUTING` 按源网段接入，具体网段由宿主机
网络拓扑决定。

TPROXY 使用独立 listener：

```sh
./build/reality_vision \
  --server 127.0.0.1 --port 8443 \
  --server_name apple.com \
  --server_public_key 'uL4rG3uX_6B359RLXYFNTmSWnrBSLVv1PIG6NUWjMVk' \
  --short_id 01234567 \
  --uuid b831381d-6324-4d53-ad4f-8cda48b30811 \
  --tproxy_port 12345
```

程序在 TCP acceptor 和 UDP socket `bind()` 前设置 `IP_TRANSPARENT`；UDP listener 还启用 `IP_RECVORIGDSTADDR`。
运行进程需要相应 Linux capability。TPROXY listener 需要 `cap_net_admin` 或 `cap_net_raw`；UDP 下行为保持原目标源端口，会将 reply socket 绑定到 original destination，因此代理 DNS/53、NTP/123 等特权端口时还需要 `cap_net_bind_service`。测试时可直接授予：

```sh
sudo setcap cap_net_admin,cap_net_raw,cap_net_bind_service=ep ./build/reality_vision
ip rule add fwmark 1 table 100
ip route replace local 0.0.0.0/0 dev lo table 100
iptables -t mangle -A PREROUTING -p tcp \
  -j TPROXY --on-port 12345 --tproxy-mark 1
iptables -t mangle -A PREROUTING -p udp --dport 53 \
  -j TPROXY --on-port 12345 --tproxy-mark 1
```

TCP transparent session 仍按原流程运行：恢复原始 IP:port，建立 REALITY，最多缓存客户端首个 16 KiB / 200 ms 做
TLS SNI / HTTP Host 探测；若得到域名，则 VLESS 使用该域名和原端口，否则使用原始 IP，随后进入现有 Vision 路径。

UDP TPROXY 不做 sniff，也不经过 Vision。listener 用 `recvmsg()` 读取 client endpoint 与 `IP_ORIGDSTADDR`，按
`(client endpoint, original destination)` 复用 UDP flow；每条 flow 建立 `REALITY -> VLESS UDP`，下行使用一个
绑定到 original destination 的透明 UDP socket，把回包以原目标 IP:port 作为源地址送回客户端。空闲 flow 当前在 120 秒后回收。

UDP/443 与其他 UDP 一样可以进入 TPROXY 并通过 VLESS UDP + REALITY 转发；当前只保持 datagram 边界，不解析 QUIC Initial、
不恢复 QUIC SNI，也不创建 Vision stream。若部署上希望浏览器/HTTP3 回落 TCP，仍可在系统规则层 REJECT UDP/443。
程序本身不管理 iptables/nftables、policy routing 或 DNS 劫持。Docker bridge 的 UDP TPROXY 还可能受到
`br_netfilter` 路径影响，和 TCP TPROXY 一样应由部署环境验证；本机/路由场景不依赖 Docker bridge。

## 基本用法

```cpp
boost::system::error_code ec;
auto executor = co_await boost::asio::this_coro::executor;

auto tcp = co_await rv::net::tcp_byte_stream::connect(
    executor, server_host, server_port, session_id, ec);
if (ec)
{
    co_return;
}

auto reality = co_await rv::reality::reality_stream::connect(
    std::move(*tcp), reality_config, session_id, ec);
if (ec)
{
    co_return;
}

auto vless = co_await rv::vless::vless_stream::connect(
    std::move(*reality), vless_config, session_id, ec);
if (ec)
{
    co_return;
}

auto stream = co_await rv::vision::vision_stream::connect(
    std::move(*vless), vless_config.user_id, session_id, ec);
if (ec)
{
    co_return;
}

co_await stream->write(data, ec);
if (ec)
{
    co_return;
}

const auto count = co_await stream->read(buffer, ec);
if (ec)
{
    co_return;
}
```

一个连接允许一个读协程和一个写协程同时运行；不允许两个并发读或两个并发写。stream 不会
为同方向操作排队，也不保证检测错误的并发调用。如果 `io_context` 由多个线程运行，调用方应让
同一连接的操作位于同一个 strand 上。

所有 Asio 操作使用 `redirect_error(use_awaitable, ec)`，因此预期的 socket 错误不会被
`use_awaitable` 转换成 `system_error`。调用方必须在每次 `co_await` 后检查 `ec`。

## 使用 Xray 配置验收

`xray x25519` 的输出映射如下：

- `PrivateKey` 只放在 Xray 服务端配置；
- `Password (PublicKey)` 传给 C++ 的 `server_public_key`；
- `Hash32` 不参与这条 REALITY client 链路。

本项目提供 SOCKS5 CONNECT/UDP ASSOCIATE、Linux IPv4 TCP REDIRECT 以及 TCP/UDP TPROXY 入站，不包含固定目标、测试 payload 或 one-shot 本地隧道模式。
使用真实 TLS 客户端验收 Vision Direct 时，让客户端通过 SOCKS5 访问 TLS 1.3 站点：

```sh
curl --proxy socks5h://test_user:test_password@127.0.0.1:1080 \
  --tlsv1.3 https://apple.com/ -v
```

日志中出现以下三项，即表明双向 Direct 边界已经实际走到：

- `vision send padding ended with command 2`；
- `reality send direction switched to raw`；
- `vision receive direction entered direct mode`。
