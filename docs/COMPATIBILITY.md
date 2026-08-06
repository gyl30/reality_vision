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

## Xray 互通测试覆盖

`tests/interop/run_xray_interop.py` 启动固定 Xray binary，并执行以下互通检查：

1. SOCKS5 domain CONNECT → REALITY + Plain VLESS → 普通 TCP echo server；
2. SOCKS5 domain CONNECT → REALITY + VLESS + Vision → 普通 TCP echo server，必须以 `command=1` 回退；
3. SOCKS5 domain CONNECT → 内层 TLS 1.2 server，必须以 `command=1` 回退且不得增加 Xray splice；
4. SOCKS5 domain CONNECT → 内层 TLS 1.3 server，必须进入双向 Direct；
5. SOCKS5 RFC 1929 正确凭据通过，错误密码被拒绝且日志不包含凭据。

第四类连接必须同时出现 TX `command=2`、TX raw switch 和 RX raw switch，否则测试失败。
第二、第三类必须出现 `command=1`，并断言对应连接没有 raw switch；TLS 1.2 用例运行前后
还会比较 Xray 的 `CopyRawConn splice` 计数。所有业务连接均通过项目唯一支持的 SOCKS5
入站完成。

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
- Vision 当前以调用方提供的写入块检测 ClientHello 和完整 application records；普通 TCP
  分片不影响数据正确性，但极端的上层切片可能使连接保守地使用 `command=1`，从而不进入
  Direct。后续指纹/流式识别模块可以独立完善这一点。
