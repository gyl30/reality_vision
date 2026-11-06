# reality-vision-cpp

一个以 C++23 协程为边界的客户端实现，当前包含：

- Boost.Asio `tcp_byte_stream`；
- REALITY 客户端握手与受限 TLS 1.3 record layer；
- VLESS TCP request 与 Xray XUDP（UDP over Mux.Cool），两者都使用固定 `xtls-rprx-vision` flow；
- XTLS-Vision padding，以及收、发方向独立切换的 Direct splice；
- 本地 SOCKS5 `CONNECT` / `UDP ASSOCIATE` 代理（支持无认证或用户名密码认证，以及域名、IPv4 和 IPv6）；
- Linux IPv4 TCP REDIRECT，以及 TCP/UDP TPROXY 透明入站；
- Linux TUN 入站：lwIP raw TCP/UDP 栈接收 IPv4/IPv6 数据包，并复用 REALITY/VLESS 出站；
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

- Xray-core `a4a3dff5b20c2faae567b742c172c7b95e75c083`（v26.10.31）；
- REALITY + VLESS + XTLS-Vision 普通 padding 帧双向传输；
- 内层 OpenSSL TLS 1.3 会话触发 Vision `command=2`；
- 外层 REALITY 的 TX/RX 分别从 TLS record mode 切换到 raw mode；
- splice 后的完整 HTTP 响应。

固定 ClientHello profile 来自 uTLS `HelloFirefox_148`（Xray `fingerprint: firefox` 的当前取值），参考提交为
`aa6edf4b11af`。当前不是泛化的指纹引擎；profile 被明确建模成
`client_hello_profile::kFirefox148`，方便以后增加更多实现。

## 支持范围

- REALITY client；
- TLS 1.3、X25519MLKEM768 与 X25519（服务端选择，REALITY 沿用 dest 站点的选择）；
- `TLS_AES_128_GCM_SHA256`；
- `TLS_AES_256_GCM_SHA384`；
- `TLS_CHACHA20_POLY1305_SHA256`；
- REALITY Ed25519 leaf certificate、HMAC-SHA512、CertificateVerify 和 Finished 校验；
- VLESS TCP 使用固定 `xtls-rprx-vision`；UDP 与 Xray vision 账户一致使用 XUDP（command `0x03` Mux，逐包携带目的/来源地址，单包上限 7526 bytes）；
- SOCKS5 `CONNECT` / `UDP ASSOCIATE` 与 RFC 1929 用户名密码认证；一个 UDP association 的所有目标共用一条 XUDP 连接；
- Vision 对内层 TLS 1.3 `0x1301..0x1304` 的 Direct 判定；
- 非 TLS TCP 和内层 TLS 1.2 通过 Vision `command=1` 回退并继续透明传输；
- IPv4、IPv6 和 domain 类型的 VLESS 目标地址；
- SOCKS 或透明入站目标为 IP 时可从 TLS ClientHello SNI 或 HTTP/1.x Host 恢复域名，探测失败保持原目标；
- Linux IPv4 TCP REDIRECT 使用 `SO_ORIGINAL_DST` 恢复 NAT 前目标；TPROXY TCP/UDP 使用 `IP_TRANSPARENT`，UDP 通过 `IP_RECVORIGDSTADDR` 获取每个 datagram 的原目标。

当前有意不支持：HelloRetryRequest、0-RTT、session resumption、KeyUpdate、
ML-DSA 附加校验和 Xray 的 spider fallback。REALITY 身份校验失败时
会直接失败，不会把连接当作普通网站 TLS 会话继续使用。

SOCKS5 当前只监听本机回环地址；不支持 `BIND`，支持 `UDP ASSOCIATE` 但不支持 SOCKS5 UDP fragmentation (`FRAG != 0`)。
透明入站当前支持 Linux IPv4 TCP REDIRECT、TCP TPROXY 和 UDP TPROXY；不实现通用 UDP REDIRECT。IPv6 transparent 和 DNS 专用劫持留到后续阶段。UDP/443 可按普通 UDP 转发，但当前不解析或 sniff QUIC。

TUN 当前是 Linux-only 的最小实现。`--tun` 使用 `/dev/net/tun`，lwIP raw API 负责 TCP/UDP 分流；TUN TCP 与 REDIRECT/TPROXY 一样，会在 200ms 内从 TLS SNI 或 HTTP Host 恢复域名，未命中时使用 IP；不做 DNS 劫持或路由规则安装。程序会把 TUN 网卡 MTU 设为 `--tun_mtu`，但不会替系统配置 TUN 的地址、路由和 DNS，部署时需要由外部脚本完成，并通过 `--mark` 策略路由或路由排除 REALITY 服务端地址避免回环。TUN 与现有 listener 共存时必须使用 `--workers 1`。

## 目录与依赖关系

```text
src/
  config.hpp / config.cpp       命令行配置结构、解析与校验
  main.cpp                      程序入口和连接运行流程
  base64.* / hex.*              配置文本解码
  reality_*                     REALITY 协议实现
  vless_* / xudp_*              VLESS 请求与 XUDP 帧实现
  vision_*                      XTLS-Vision 实现
  socks5_protocol.*             SOCKS5 协议实现
  sniffer.*                     TLS SNI / HTTP Host 目标探测
  transparent.*                 Linux REDIRECT / TPROXY socket helper
  tun_device.* / tun_inbound.*  Linux TUN 设备与 lwIP raw 入站
  tun_lwip.* / tun_*_session.*  lwIP 地址转换及 TCP / UDP 会话
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

TUN IPv4 / IPv6 packet
    -> lwIP raw TCP / UDP -> VLESS TCP / XUDP -> Vision / REALITY

UDP:
SOCKS5 UDP ASSOCIATE / TPROXY UDP
    -> UDP session（每个客户端源地址）-> XUDP -> Vision -> REALITY -> TCP transport

XUDP frames never trigger Vision Direct; UDP only uses Vision padding.

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
- 提供 `spdlog::spdlog` 的 spdlog CMake package。

BoringSSL 与 lwIP 以 Git submodule 固定版本源码随工程构建；CMake 不下载依赖，Boost 与 spdlog 直接使用本机已经安装的包。

首次构建前初始化 Git submodule：

```sh
git submodule update --init --recursive
```

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j12
ctest --test-dir build --output-on-failure
```

CMake 只创建一个 `reality_vision` executable，所有实现源文件直接编入该目标。它直接链接：

- `Boost::headers`；
- `spdlog::spdlog`；
- BoringSSL `crypto`（submodule `third/boringssl`）；
- `Threads::Threads`；
- `Boost::program_options`；
- `Boost::system`。

工程只链接 BoringSSL 的 libcrypto；普通 OpenSSL 不提供实现所用的 `EVP_AEAD` 等接口。

主要 CMake 开关：

- `RV_BUILD_TESTS=ON|OFF`；
- `RV_XRAY_EXECUTABLE=/path/to/xray`：启用真实 Xray 互通测试。
- `RV_ENABLE_PRIVILEGED_TESTS=ON|OFF`：注册需要 network namespace 的 REDIRECT/TPROXY 与 TUN 互通测试。

协议自测已经编入同一个二进制，也可以直接运行 `./build/reality_vision --self_test`。
Xray 互通测试覆盖 SOCKS5 非 TLS、TCP half-close 后继续接收回程数据、TLS 1.2 fallback、TLS 1.3 Direct、IP 目标 TLS SNI sniff、Vision framing，
并验证 SOCKS5 IPv6 TCP echo、正确/错误密码、`UDP ASSOCIATE -> XUDP -> UDP echo`、7526/7527 bytes 边界、多个目标共用一条 XUDP 连接以及 UDP/443 request；还需要 Python 3 和系统的 OpenSSL 命令行工具。
特权测试额外在隔离 network namespace 中配置真实 TCP REDIRECT 与 TCP/UDP TPROXY；启用后使用
`sudo ctest --test-dir build -R rv_transparent_interop --output-on-failure` 单独运行。
`rv_tun_interop` 总是通过 `unshare -Urnm` 进入新的 user/net/mount namespace，宿主允许非特权 user namespace 时无需 root；
它在 TUN 上验证 IPv4/IPv6 TCP，以及同一 UDP 源端口访问多个目标时共用一条 XUDP 连接、回包来自各自的目标。

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
  --workers 2 \
  --socks_username test_user \
  --socks_password test_password
```

`--short_id` 与 Xray 的 REALITY 配置保持一致：允许 0～16 个十六进制字符，非空时必须为偶数长度；不足 8 字节的部分在尾部补 0。

`--tcp_idle_timeout` 为 TCP 中继双向都没有数据时的关闭时间（秒），默认 300，与 Xray `connIdle` 一致，0 表示不限制；适用于 SOCKS5、REDIRECT/TPROXY 与 TUN。

`--workers` 为独立 `io_context` 的数量，默认是 1。设置为大于 1 时，每个 worker 为已配置的 listener 创建独立 socket，Linux 内核通过 `SO_REUSEPORT` 分发连接；各 worker 不共享连接和 flow 容器，也不使用 strand。

这条命令监听 `127.0.0.1:1080`。使用 `socks5h` 时 SOCKS 请求直接携带域名，不需要额外探测：

```sh
curl --proxy socks5h://test_user:test_password@127.0.0.1:1080 https://apple.com/ -v
```

SOCKS `REP=0` 表示本地已完成 REALITY 握手；域名目标还已发送 VLESS/Vision 初始化数据，但不保证 Xray 已连接最终目标。
VLESS 没有最终目标连接状态字段；域名解析、目标建连或 VLESS 鉴权失败可能在成功回复后以 EOF/RST 表现。
对于无响应目标，关闭时间还受配置的 TCP 空闲超时影响。不能通过等待 VLESS response header 实现可靠的 CONNECT 确认：
该头部可能随下行数据才被刷出，而客户端会等待 SOCKS 回复后才发送首包。

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
association 的首个 datagram 建立一条 `REALITY -> Vision -> XUDP` 连接，此后 SOCKS5 UDP header 中的目标地址/端口逐包写入 XUDP 帧，
发往任意目标都复用这条连接；回包的 SOCKS5 header 使用服务端回报的来源地址。上游连接 120 秒无活动后关闭，下一个 datagram 重新建立。
超过 7526 bytes 的 datagram 被丢弃。SOCKS5 `FRAG != 0` 当前拒绝。UDP/443 与其他 UDP 使用相同的 XUDP + REALITY 路径。

## 作为 Linux TUN 入站运行

`--tun` 会创建指定名称的 Linux TUN 设备，默认名称为 `rv-tun`，并把网卡与 lwIP 的 MTU 都设为 `--tun_mtu`（默认 8500，与 hev-socks5-tunnel 相同）：

```sh
sudo ./build/reality_vision \
  --server 127.0.0.1 --port 8443 \
  --server_name apple.com \
  --server_public_key 'uL4rG3uX_6B359RLXYFNTmSWnrBSLVv1PIG6NUWjMVk' \
  --short_id 01234567 \
  --uuid b831381d-6324-4d53-ad4f-8cda48b30811 \
  --tun --tun_name rv-tun --mark 1
```

`--tun_name` 最多为 15 字节，超长名称明确拒绝；空字符串仍由内核分配设备名，程序保存并记录内核返回的实际名称。

进程需要访问 `/dev/net/tun` 的权限，通常需要 root 或 `CAP_NET_ADMIN`；`--mark` 设置出站 REALITY 连接的 `SO_MARK`，
同样需要 `CAP_NET_ADMIN`。设备创建后，还需要在另一个终端设置系统侧地址、链路和路由；这些参数必须与部署拓扑匹配。
下面的策略路由把未打标记的流量送入 TUN，带 `--mark 1` 的 REALITY 连接仍走主路由表：

```sh
sudo ip addr add 198.18.0.1/15 dev rv-tun
sudo ip link set dev rv-tun up
sudo ip route add default dev rv-tun table 100
sudo ip rule add not fwmark 1 lookup 100
```

不使用 `--mark` 时，路由必须单独排除 REALITY 服务端地址。`--server` 为域名时只在启动时用系统解析器解析一次，之后所有出站连接
都使用这次解析得到的地址，因此路由切到 TUN 后不会再发出服务端域名的 DNS 查询；启动时解析失败会直接退出，服务端 IP 变化后需要重启。

默认路由会把代理自身的 REALITY 连接也送回 TUN，生产配置必须使用策略路由或防火墙规则排除服务端地址。TUN UDP 同一客户端源 IP/端口访问的所有目标共用一条 XUDP 连接（空闲 120 秒回收），单包上限 7526 bytes。默认 MTU 8500 下这些数据报无需 IP 分片；lwIP 最多重组 4 个 IP 分片，若改小 `--tun_mtu`（例如 1500），超过约 5.9 KB 的 UDP 数据报会在重组阶段丢弃；TCP 会按 lwIP 的接收窗口和发送窗口回压。

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

也可以不依赖运行用户：启动时加 `--mark 1`，把 owner 规则换成 `iptables -t nat -A OUTPUT -p tcp -m mark --mark 1 -j RETURN`。

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

UDP TPROXY 不做 sniff。listener 用 `recvmsg()` 读取 client endpoint 与 `IP_ORIGDSTADDR`，每个 client endpoint 一条
`REALITY -> Vision -> XUDP` 连接，原目标逐包写入 XUDP 帧；下行按服务端回报的来源地址创建绑定该地址的透明 UDP socket
（每个会话最多 256 个），把回包以原目标 IP:port 作为源地址送回客户端。空闲会话在 120 秒后回收。

UDP/443 与其他 UDP 一样可以进入 TPROXY 并通过 XUDP + REALITY 转发；当前只保持 datagram 边界，不解析 QUIC Initial，
也不恢复 QUIC SNI。若部署上希望浏览器/HTTP3 回落 TCP，仍可在系统规则层 REJECT UDP/443。
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
