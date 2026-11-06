# 兼容性基线

## 固定参考版本

| 项目 | revision | 用途 |
|---|---|---|
| Xray-core | `a4a3dff5b20c2faae567b742c172c7b95e75c083`（v26.10.31） | REALITY、VLESS、Vision 互通基线 |
| uTLS | `aa6edf4b11af` | `HelloFirefox_148` 序列化 profile |
| XTLS/REALITY Go | `83f621788ca8` | 服务端 REALITY 行为参考 |
| BoringSSL | `0.20261020.0`（`d3bf4795ad5b79d646cddf2fec687da5b9b502db`） | submodule 固定的密码学与 X.509 版本 |
| spdlog | `1.15.3` | 已验证的日志库版本 |
| Boost | `1.86.0` | 已验证的 Asio/System/ProgramOptions 版本 |

BoringSSL 与 lwIP 由 Git submodule 固定版本并随工程源码构建；Boost 与 spdlog 由调用方安装。CMake 不下载第三方依赖。

## Firefox 148 profile

当前 profile 对应 uTLS `HelloFirefox_148`，也是 Xray `fingerprint: firefox` 的当前取值。TLS 1.3 cipher preference 固定为：

1. `TLS_AES_128_GCM_SHA256`；
2. `TLS_CHACHA20_POLY1305_SHA256`；
3. `TLS_AES_256_GCM_SHA384`。

同时保留 Firefox 的 TLS 1.2 cipher list，以保持 ClientHello 外形。扩展顺序为：

1. SNI；
2. extended master secret；
3. renegotiation info；
4. supported groups（`X25519MLKEM768`、`X25519`、P-256、P-384、P-521、ffdhe2048、ffdhe3072）；
5. EC point formats；
6. ALPN；
7. status request；
8. delegated credentials；
9. signed certificate timestamp；
10. key share；
11. supported versions；
12. signature algorithms；
13. record size limit；
14. compress certificate（zlib、brotli、zstd）；
15. GREASE ECH。

KeyShare 依次包含 `X25519MLKEM768`（1184-byte ML-KEM-768 encapsulation key ‖ X25519 public key）、
X25519 与 P-256 public share；两处 X25519 复用同一把密钥，与 uTLS `ReuseHybridAndClassicalKeyShares` 一致。
新版 REALITY 服务端要求 `X25519MLKEM768` 出现在独立 X25519 之前，并用该 X25519 公钥完成 REALITY 认证。

REALITY 服务端沿用 dest 站点 ServerHello 选择的 group：选择 `X25519MLKEM768` 时 server share 为
1088-byte ML-KEM 密文 ‖ X25519 public key，共享密钥为 ML-KEM shared secret ‖ X25519 shared secret；
选择 X25519 时只做 X25519。服务端选择 P-256 或发送 HelloRetryRequest 时，连接通过
`boost::system::errc::operation_not_supported` 失败。compress certificate 只用于指纹外形：REALITY 服务端基于 Go TLS，
不会发送 CompressedCertificate。

GREASE ECH 保持 uTLS profile 的字段形状和 239-byte ciphertext 长度。它只用于指纹外形，
不是一次真实 ECH 尝试。

REALITY `shortId` 与 Xray 固定基线保持一致：允许 0～8 字节，命令行使用 0～16 个十六进制字符表示，
非空时必须为偶数长度；不足 8 字节时在尾部补 0。互通测试使用 4-byte `shortId`，覆盖该补零路径。

## Xray 互通测试覆盖

`tests/interop/run_xray_interop.py` 启动固定 Xray binary，并执行以下互通检查。REALITY dest 使用同一 Xray 进程中的 Go TLS
inbound：新版 REALITY 自身的 EncryptedExtensions 总会 ack SNI，dest 也必须 ack，否则握手长度不一致；
默认 dest 优先协商 `X25519MLKEM768`，另一个 dest 只允许 X25519，两条密钥交换路径都会断言。


1. SOCKS5 domain CONNECT → REALITY + VLESS + Vision → 普通 TCP echo server，必须以 `command=1` 回退；
2. SOCKS5 domain CONNECT → 内层 TLS 1.2 server，必须以 `command=1` 回退且不得增加 Xray splice；
3. SOCKS5 domain CONNECT → 内层 TLS 1.3 server，必须进入双向 Direct；
4. SOCKS5 IP CONNECT → TLS 1.3 server，验证 SNI sniff 后仍进入 Direct；
5. SOCKS5 RFC 1929 正确凭据通过，错误密码被拒绝且日志不包含凭据；
6. SOCKS5 无认证 listener 使用 `NO AUTH` 完成 TCP echo 往返，验证未配置用户名/密码时的真实代理链路；
7. SOCKS5 UDP ASSOCIATE → XUDP（Vision flow）→ UDP echo server，验证 XUDP 帧编解码、7526/7527 bytes 边界，以及
   IPv4、IPv6、域名目标共用一条 XUDP 连接且回包头携带来源地址，并发送 UDP/443 请求确认 Xray 收到。

TLS 1.3 Direct 用例必须同时出现 TX `command=2`、TX raw switch 和 RX raw switch，否则测试失败。普通 TCP/TLS 1.2 必须出现
`command=1` 并断言没有 raw switch；TLS 1.2 用例运行前后还会比较 Xray 的 `CopyRawConn splice` 计数。UDP 用例通过 SOCKS5
association 生命周期关闭上游 flow，不依赖 transparent/netfilter 权限。

运行方式：

```sh
cmake -S . -B build \
  -DRV_XRAY_EXECUTABLE=/absolute/path/to/xray
cmake --build build
ctest --test-dir build --output-on-failure
```

## 有意差异

- Xray/uTLS 在 REALITY 验证失败后可把连接当作普通站点连接执行 spider；本实现 fail closed。
- 当前忽略 REALITY certificate 中可选的 ML-DSA extension，不提供 PQ 附加认证保证。
- 不实现 session tickets、0-RTT、KeyUpdate 或自动 key update。
- 指纹是固定 profile，不会根据浏览器版本或站点动态选择。
- Vision 发送方向使用增量 TLS record tracker，跨多次写调用保存部分 record header、剩余
  payload 长度和 ClientHello 判定状态。TLS record 被 TCP 拆分、多个 record 合并到同一次写入，
  或加密 record 从某次写入中间结束时，都能在准确的 record 边界结束 padding 或切换 Direct。

接收方向的 ServerHello 识别独立重组 Handshake 消息：支持四字节 Handshake 头与消息体跨多条 TLS record、
TCP 任意分片及同批多 record。识别最多观察 64 KiB，单条 record 与重组消息各限制为 16 KiB（record header 另计）；
超限、非法续接或不支持的消息保持非 Direct 回退。重组副本只用于识别，原始 TLS 字节仍按原顺序交付。
真实 Xray 互通测试另用受控中继把 OpenSSL ServerHello 拆为四条 record，验证内层 TLS 握手、HTTP 往返及客户端 uplink Direct。
固定 Xray 自身对该分片形式仍选择 downlink fallback，因此该用例不宣称双向 Direct；常规 TLS 1.3 用例继续验证双向 Direct。

## 透明入站兼容范围

透明代理当前实现 Linux IPv4：

- TCP REDIRECT：依赖 netfilter conntrack 的 `SO_ORIGINAL_DST`；
- TCP TPROXY：listener 在 `bind()` 前设置 `SOL_IP/IP_TRANSPARENT`，目标从 accepted socket local endpoint 取得；
- UDP TPROXY：同一 `--tproxy_port` 建立 UDP listener，设置 `IP_TRANSPARENT` 与 `IP_RECVORIGDSTADDR`，通过 `recvmsg()` 获取每包原目标；
- UDP downlink 使用绑定回包来源地址（通常即 original destination）的透明 socket，保持返回客户端时的源 IP:port；绑定 DNS/53、NTP/123 等低于 1024 的端口时进程需要 `CAP_NET_BIND_SERVICE`；
- SOCKS5 UDP association、TPROXY UDP 与 TUN UDP 都按客户端源地址使用一条 XUDP 连接，逐包携带目的地址；120 秒 idle timeout；
- iptables/nftables、TPROXY fwmark/policy routing、进程自身绕行规则由部署环境负责；
- 通用 UDP REDIRECT、IPv6 REDIRECT/TPROXY 和 DNS 专用 redirect 不属于当前阶段；UDP/443 可透明转发，但 QUIC 协议解析/sniff 不实现。

TCP REDIRECT/TPROXY 得到 IP 目标后复用 destination sniffer；SNI/HTTP Host 命中时 VLESS 改用域名，否则保持原 IP。UDP 不 sniff，
直接使用 SOCKS5 UDP header 或 TPROXY original destination。UDP 与 Xray vision 账户的出站一致，使用 XUDP：VLESS command `0x03`
(Mux)、`xtls-rprx-vision` flow，Mux.Cool New/Keep 帧逐包携带目的地址，下行 Keep 帧携带来源地址。零长度 UDP datagram 当前不转发。
固定 Xray 基线（v26.10.31）的 XUDP writer 跳过 `length + 666 > 8192` 的 datagram，服务端拒绝超过 8192 bytes 的 datagram，
因此发送端丢弃超过 7526 bytes 的 payload。对域名目标，Xray 对会话首个目标回报原域名，对后续 Keep 帧目标回报解析后的 IP，
SOCKS5 回包头按服务端回报原样转发。
真实 transparent UDP 测试需要 root/netfilter/capability，
因此不放入默认 CTest；启用 `RV_ENABLE_PRIVILEGED_TESTS` 后，独立 network namespace 测试会覆盖 TCP REDIRECT、TCP/UDP TPROXY、
透明 UDP 源地址、53 端口、空 datagram、7526/7527 bytes 边界，以及阻断新 REALITY 连接后新目标仍经已有 XUDP 连接收发。
默认 interop 仍通过无特权 SOCKS5 UDP ASSOCIATE 覆盖相同的 XUDP/REALITY 协议路径。

Docker bridge 上的 TPROXY 还取决于宿主机 `br_netfilter` 路径；该环境问题与应用是否正确设置 `IP_TRANSPARENT` 是两件事，
部署时应单独验证。UDP/443 使用与其他 UDP 相同的 XUDP + REALITY 路径；默认测试额外验证 SOCKS5 UDP/443 请求能到达 Xray，但不要求测试环境绑定本地特权端口 443。真实 QUIC/HTTP3 应另做端到端验证。
