# 兼容性基线

## 固定参考版本

| 项目 | revision | 用途 |
|---|---|---|
| Xray-core | `5ca6f4b7d4dc20a881d4330e498892697627ec0c` | REALITY、VLESS、Vision 互通基线 |
| uTLS | `aa6edf4b11af` | `HelloFirefox_120` 序列化 profile |
| XTLS/REALITY Go | `9234c772ba8f` | 服务端 REALITY 行为参考 |
| BoringSSL | `619e6bc3deda4e0d2fe4ad3fc439ae4fc1e00caf` | 已验证的密码学与 X.509 版本 |
| spdlog | `1.15.3` | 已验证的日志库版本 |
| Boost | `1.86.0` | 已验证的 Asio/System/ProgramOptions 版本 |

调用方负责安装这些依赖并保证 BoringSSL 与兼容基线一致；CMake 不下载或编译第三方库。

## Firefox 120 profile

当前 profile 固定以下 TLS 1.3 cipher preference：

1. `TLS_AES_128_GCM_SHA256`；
2. `TLS_CHACHA20_POLY1305_SHA256`；
3. `TLS_AES_256_GCM_SHA384`。

同时保留 Firefox 120 的 TLS 1.2 cipher list，以保持 ClientHello 外形。扩展顺序为：

1. SNI；
2. extended master secret；
3. renegotiation info；
4. supported groups；
5. EC point formats；
6. session ticket；
7. ALPN；
8. status request；
9. delegated credentials；
10. key share；
11. supported versions；
12. signature algorithms；
13. PSK key exchange modes；
14. record size limit；
15. GREASE ECH。

KeyShare 包含 X25519 与 P-256 public share。REALITY key agreement 当前只保存 X25519
private key；如果服务端选择 P-256 或发送 HelloRetryRequest，连接会通过
`boost::system::errc::operation_not_supported` 失败。

GREASE ECH 保持 uTLS profile 的字段形状和 239-byte ciphertext 长度。它只用于指纹外形，
不是一次真实 ECH 尝试。

REALITY `shortId` 与 Xray 固定基线保持一致：允许 0～8 字节，命令行使用 0～16 个十六进制字符表示，
非空时必须为偶数长度；不足 8 字节时在尾部补 0。互通测试使用 4-byte `shortId`，覆盖该补零路径。

## Xray 互通测试覆盖

`tests/interop/run_xray_interop.py` 启动固定 Xray binary，并执行以下互通检查：

1. SOCKS5 domain CONNECT → REALITY + VLESS + Vision → 普通 TCP echo server，必须以 `command=1` 回退；
2. SOCKS5 domain CONNECT → 内层 TLS 1.2 server，必须以 `command=1` 回退且不得增加 Xray splice；
3. SOCKS5 domain CONNECT → 内层 TLS 1.3 server，必须进入双向 Direct；
4. SOCKS5 IP CONNECT → TLS 1.3 server，验证 SNI sniff 后仍进入 Direct；
5. SOCKS5 RFC 1929 正确凭据通过，错误密码被拒绝且日志不包含凭据；
6. SOCKS5 无认证 listener 使用 `NO AUTH` 完成 TCP echo 往返，验证未配置用户名/密码时的真实代理链路；
7. SOCKS5 UDP ASSOCIATE → VLESS UDP（empty flow）→ UDP echo server，验证 datagram request/response framing，
   且该 flow 日志不得出现 Vision；另验证文本相同的 domain/IPv4 目标不会错误复用 flow，并发送 UDP/443 请求确认 Xray 收到。

TLS 1.3 Direct 用例必须同时出现 TX `command=2`、TX raw switch 和 RX raw switch，否则测试失败。普通 TCP/TLS 1.2 必须出现
`command=1` 并断言没有 raw switch；TLS 1.2 用例运行前后还会比较 Xray 的 `CopyRawConn splice` 计数。UDP 用例通过 SOCKS5
association 生命周期关闭上游 flow，不依赖 transparent/netfilter 权限。

运行方式：

```sh
cmake -S . -B build \
  -DRV_XRAY_EXECUTABLE=/absolute/path/to/xray \
  -DOpenSSL_DIR=/absolute/path/to/boringssl/lib/cmake/OpenSSL
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

## 透明入站兼容范围

透明代理当前实现 Linux IPv4：

- TCP REDIRECT：依赖 netfilter conntrack 的 `SO_ORIGINAL_DST`；
- TCP TPROXY：listener 在 `bind()` 前设置 `SOL_IP/IP_TRANSPARENT`，目标从 accepted socket local endpoint 取得；
- UDP TPROXY：同一 `--tproxy_port` 建立 UDP listener，设置 `IP_TRANSPARENT` 与 `IP_RECVORIGDSTADDR`，通过 `recvmsg()` 获取每包原目标；
- UDP downlink 使用绑定 original destination 的透明 socket，保持返回客户端时的源 IP:port；绑定 DNS/53、NTP/123 等低于 1024 的原目标端口时进程需要 `CAP_NET_BIND_SERVICE`；
- SOCKS5 UDP flow 按 `(address type, destination, port)` 复用，TPROXY UDP flow 按 `(client endpoint, original destination)` 复用；两者都是 120 秒 idle timeout；
- iptables/nftables、TPROXY fwmark/policy routing、进程自身绕行规则由部署环境负责；
- 通用 UDP REDIRECT、IPv6 REDIRECT/TPROXY 和 DNS 专用 redirect 不属于当前阶段；UDP/443 可透明转发，但 QUIC 协议解析/sniff 不实现。

TCP REDIRECT/TPROXY 得到 IP 目标后复用 destination sniffer；SNI/HTTP Host 命中时 VLESS 改用域名，否则保持原 IP。UDP 不 sniff，
直接使用 SOCKS5 UDP header 或 TPROXY original destination；VLESS UDP 使用 command `0x02`、empty flow 和 2-byte datagram length，
不会创建 Vision stream。零长度 UDP datagram 当前不转发。固定 Xray 基线（v26.7.28）的标准 VLESS UDP writer 使用 8192-byte
buffer，并跳过 `length + 2 > 8192` 的 datagram，因此发送端拒绝超过 8190 bytes 的 payload，保证双向边界一致。
真实 transparent UDP 测试需要 root/netfilter/capability，
因此不放入默认 CTest；默认 interop 通过无特权 SOCKS5 UDP ASSOCIATE 覆盖相同的 VLESS UDP/REALITY 协议路径。

Docker bridge 上的 TPROXY 还取决于宿主机 `br_netfilter` 路径；该环境问题与应用是否正确设置 `IP_TRANSPARENT` 是两件事，
部署时应单独验证。UDP/443 使用与其他 UDP 相同的 VLESS UDP + REALITY 路径；默认测试额外验证 SOCKS5 UDP/443 请求能到达 Xray，但不要求测试环境绑定本地特权端口 443。真实 QUIC/HTTP3 应另做端到端验证。
