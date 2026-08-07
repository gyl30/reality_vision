# reality-vision-cpp

一个以 C++23 协程为边界的客户端实现，当前包含：

- Boost.Asio `tcp_byte_stream`；
- REALITY 客户端握手与受限 TLS 1.3 record layer；
- VLESS TCP request 与固定的 `xtls-rprx-vision` addon；
- XTLS-Vision padding，以及收、发方向独立切换的 Direct splice；
- 本地 SOCKS5 TCP CONNECT 代理（支持无认证或用户名密码认证，以及域名、IPv4 和 IPv6）；
- IPv4/IPv6 SOCKS 目标的轻量 destination sniffer（TLS SNI / HTTP Host）；
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
- VLESS TCP 与固定的 `xtls-rprx-vision`；
- SOCKS5 `CONNECT` 与 RFC 1929 用户名密码认证，每个本地连接独立建立一条远端协议栈；
- Vision 对内层 TLS 1.3 `0x1301..0x1304` 的 Direct 判定；
- 非 TLS TCP 和内层 TLS 1.2 通过 Vision `command=1` 回退并继续透明传输；
- IPv4、IPv6 和 domain 类型的 VLESS 目标地址；
- SOCKS 请求为 IP 时可从 TLS ClientHello SNI 或 HTTP/1.x Host 恢复域名，探测失败保持原目标。

当前有意不支持：HelloRetryRequest、0-RTT、session resumption、KeyUpdate、
X25519MLKEM768、ML-DSA 附加校验和 Xray 的 spider fallback。REALITY 身份校验失败时
会直接失败，不会把连接当作普通网站 TLS 会话继续使用。

SOCKS5 当前只监听本机回环地址；不支持 `BIND` 或 UDP `ASSOCIATE`。

## 目录与依赖关系

```text
src/
  config.hpp / config.cpp       命令行配置结构、解析与校验
  main.cpp                      程序入口和连接运行流程
  base64.* / hex.*              文本编解码
  reality_*                     REALITY 协议实现
  vless_*                       VLESS 协议实现
  vision_*                      XTLS-Vision 实现
  socks5_protocol.*             SOCKS5 协议实现
  sniffer.*                     TLS SNI / HTTP Host 目标探测
  tcp_byte_stream.*             TCP 字节流
  crypto.*                      BoringSSL 封装
  protocol_tests.*              内置协议自测

tests/interop/                  Xray 互通测试脚本
docs/                           架构与兼容性说明
```

```text
vision_stream -> vless_stream -> reality_stream -> tcp_byte_stream -> Boost.Asio TCP
                              |
                              +-------------> crypto wrapper -> BoringSSL

SOCKS5 client -> TCP CONNECT parser -> one protocol stack per connection

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
Xray 互通测试覆盖 SOCKS5 非 TLS、TLS 1.2 fallback、TLS 1.3 Direct、IP 目标 TLS SNI sniff 和 Vision
framing，并验证 SOCKS5 正确密码与错误密码；还需要 Python 3 和系统的 OpenSSL 命令行工具。

## 作为 SOCKS5 TCP 代理运行

启动 Xray 服务端后运行：

```sh
./build/reality_vision \
  --server 127.0.0.1 --port 8443 \
  --server_name apple.com \
  --server_public_key 'uL4rG3uX_6B359RLXYFNTmSWnrBSLVv1PIG6NUWjMVk' \
  --short_id 0123456789abcdef \
  --uuid b831381d-6324-4d53-ad4f-8cda48b30811 \
  --socks_port 1080 \
  --socks_username test_user \
  --socks_password test_password
```

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

该模式会持续 accept，并为每个 SOCKS5 TCP CONNECT 请求独立创建
`tcp_byte_stream -> reality_stream -> vless_stream -> vision_stream`。客户端或远端 EOF 会按
TCP half-close 传播，另一方向继续排空后再释放连接。

## 基本用法

```cpp
boost::system::error_code ec;
auto executor = co_await boost::asio::this_coro::executor;

auto tcp = co_await rv::net::tcp_byte_stream::connect(
    executor, server_host, server_port, session_id, ec);
if (ec || !tcp)
{
    co_return;
}

auto reality = co_await rv::reality::reality_stream::connect(
    std::move(*tcp), reality_config, session_id, ec);
if (ec || !reality)
{
    co_return;
}

auto vless = co_await rv::vless::vless_stream::connect(
    std::move(*reality), vless_config, session_id, ec);
if (ec || !vless)
{
    co_return;
}

auto stream = co_await rv::vision::vision_stream::connect(
    std::move(*vless), vless_config.user_id, session_id, ec);
if (ec || !stream)
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

本项目只提供 SOCKS5 入站，不再包含固定目标、测试 payload 或 one-shot 本地隧道模式。
使用真实 TLS 客户端验收 Vision Direct 时，让客户端通过 SOCKS5 访问 TLS 1.3 站点：

```sh
curl --proxy socks5h://test_user:test_password@127.0.0.1:1080 \
  --tlsv1.3 https://apple.com/ -v
```

日志中出现以下三项，即表明双向 Direct 边界已经实际走到：

- `vision send padding ended with command 2`；
- `reality send direction switched to raw`；
- `vision receive direction entered direct mode`。
