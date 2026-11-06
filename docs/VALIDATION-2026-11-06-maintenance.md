# 功能正确性定向维护验收

## 1. 本地基线

- 仓库：`/home/gyl/example/reality_vision`，分支 `main`。
- 本地 HEAD、origin/main 和 `git ls-remote origin refs/heads/main` 均为
  `f6f4193d5c2c91c9ecfd6350bac993b79695df13`。
- 初始工作区、暂存区均为空；没有覆盖其他未提交工作。
- Linux `6.8.0-138-generic`，GCC `16.2.0`，CMake `3.31.10`，Debug，`-j4` 构建。
- 证据目录 M：`/tmp/rv-maintenance-20261106`；复用的构建目录 B：`/tmp/rv-review-20261106`。
- 固定 Xray 源码：`/home/gyl/data/code/Xray-core`，提交
  `a4a3dff5b20c2faae567b742c172c7b95e75c083`。
  复用上轮从该源码构建的 `B/xray-a4a3dff`，本轮核对 SHA-256 与上轮记录一致；不是源码目录中原有的旧版 xray。

| 对象 | SHA-256 |
|---|---|
| Xray 26.10.31 / Go 1.27.3 | `f407ab1a09330c4400b41f6a7516e74f3c6adf4e3ffd0f65a335e8472c2bf1bd` |
| 基线客户端 M/baseline | `48f252f0c41a0f6d15b26479545d91e9996c0ddfbfe6b8bb378c6bf013e30dd0` |
| 最终 Debug 客户端 B/reality_vision | `f63cf29906956d543b78a38e80804e40d6c9c208c3f91c16561ebc777ce55d2f` |

## 2. 问题核实

| 任务 | 状态 | 结论 |
|---|---|---|
| A：同源多目标因多 worker 产生额外 XUDP | NOT REPRODUCED | 基线和最终客户端在已测内核及拓扑下都保持每个来源一条连接；没有据推测修改 UDP listener 放置 |
| A：多 worker 数据丢失或错投 | NOT REPRODUCED | 1/2/4 worker、两个固定来源、两个目标 IP、16 个目标端口、并发与交替发送全部通过 |
| A：空闲关闭及同源重建 | 已验证 | 真实等待 125 秒，观察旧上游 TCP 连接关闭；重建后 GlobalID 不变，两个来源不共享 ID |
| B：长 TUN 名称被静默截断 | CONFIRMED → FIXED | 16/42 字节输入原先创建截短名称；现在配置退出 1，且不创建设备 |
| C：目标失败仍可能 REP=0 | CONFIRMED / BY DESIGN | 固定 Xray/VLESS 没有可靠的最终目标连接状态信号；保留回复时序，补文档和测试 |
| 既有 ServerHello、TUN RST、namespace 修复 | 保持原实现 | 只做回归，未重复开发 |

## 3. 复现证据

### A：实际调用链与对照

`service::startup()` 为每个 worker 创建 UDP TPROXY socket，使用 SO_REUSEPORT。
`udp_tproxy::receive_datagrams()` 通过 recvmsg 获取客户端来源与原目标，交给 worker 内的 `get_session(client)`。
会话表仅以客户端 IP:Port 为键；`xudp::make_global_id()` 以进程级随机密钥对来源字符串做 HMAC。
`xudp_stream` 首包发送 New，此后 Keep 帧逐包携带目标。

不能仅凭 socket 数量或目标不同断定内核一定分散同一来源。实际测试包括单入口及双入口：
双入口客户端固定绑定 `10.203.0.2:41001/41002`，第二个目标经另一条 veth 接入同一代理。
目标为 `10.204.0.2/10.204.0.3` 的 `7000..7015`，逐目标使用绑定该确切 IP 的 echo 服务。
每轮进行三个发送阶段，每来源每批最多 8 包，两个来源并发；192 个带唯一标识的完整 payload 全部核对内容和来源地址。
另有两个预热及两个空闲重建交换。没有扩大队列、资源限制或缩短生产 idle timeout。

测试准备时曾发现通配地址 echo 服务对第二个目标使用主 IP 回包；这属于测试服务器设置，不能作为代理错投证据。
修正为每个目标 IP 独立绑定后，保留严格来源断言。新增 worker 场景后的空 datagram 检查比较会话计数前后不变，
避免将先前场景的已有会话误算为空包创建；默认场景仍要求零会话。

基线和最终版本均没有复现任务 A，因此没有制造 A 的 RED，也未修改 service/udp_proxy/xudp_stream 生产逻辑。

### B：真实 RED

```bash
python3 tests/interop/test_tun_names.py \
  --client /tmp/rv-maintenance-20261106/baseline \
  --work-dir /tmp/rv-maintenance-20261106/red-tun-names
```

脚本自动进入私有 user/network/mount namespace。基线结果：

- 默认名称创建 `rv-tun`；空名称创建内核分配的 `tun0`。
- 15 字节名称 `rv1234567890123` 原样创建。
- 16 字节名称 `rv12345678901234` 被截断为 `rv1234567890123`，进程继续运行，测试失败。
- 42 字节名称也被截断，进程继续运行，测试失败。

原始失败保存在 M/red-tun-names.log，每个失败轮次也在 finally 停止进程并确认设备消失。

### C：真实 Xray CONNECT 观察

`run_socks_connect_semantics.py` 使用独立 namespace、本地 NXDOMAIN DNS 服务，以及仅在该 namespace 中的 SYN 丢弃规则。
正常目标逐字节 echo 核对；失败目标核对 Xray 的实际错误日志，不只检查 REP。

| 场景 | REP | 目标/服务端结果 | 客户端后续 |
|---|---:|---|---|
| 正常域名 | 0 | 连接成功、完整 payload 往返 | 半关闭后 EOF |
| 正常 IP | 0 | 连接成功、完整 payload 往返 | 半关闭后 EOF |
| 不存在域名 | 0 | 受控 DNS NXDOMAIN，Xray rcode=3 | EOF |
| IP 目标端口拒绝 | 0 | Xray connect: connection refused | EOF |
| IP 目标无响应 | 0 | SYN 丢弃规则命中，dial 尚未完成 | 客户端配置的 2 秒 idle 关闭后 EOF |
| REALITY 鉴权失败 | 1 | 客户端拒绝 REALITY 认证，未发送 VLESS 请求 | 失败 REP |
| VLESS UUID 鉴权失败 | 0 | Xray invalid request user id | EOF |
| IP CONNECT 后发送带 SNI 的 ClientHello | 0 | REP 后嗅探到 missing.invalid，最终 DNS 失败 | EOF |

每例的 REP 相对时间（毫秒级）、终止相对时间、REALITY/VLESS 发送状态、服务端日志及 fd 计数记录在
B/socks-connect-semantics/results.json 和同目录分场景日志中；基线对照在 M/socks-baseline。
`server_connect_logged_at_rep` 仅表示当时日志中是否已出现连接成功标记，不把日志可见时间当作网络事件的精确发生时间。
IP CONNECT 在 REP 时尚未发送 VLESS 请求，后续首包仍按原机制参与嗅探。

固定源码依据：`proxy/vless/encoding/encoding.go` 的 Encode/DecodeResponseHeader 只处理版本与 addon；
`proxy/vless/inbound/inbound.go` 在 DispatchLink 前将 response header 编码进 BufferedWriter，设置后续写入刷出。
“编码”不等于立即在网络发送。头部没有目标连接成功/失败字段，也不是独立 ACK；等待头部还可能阻塞等待客户端首包的目标协议。
因此不改变 SOCKS 回复、首包 sniff、Direct 或半关闭流程。

## 4. 修改说明

生产代码只修改两处：

- `src/config.cpp`：按 Linux IFNAMSIZ=16（含终止 NUL）拒绝长度达到 16 字节的名称，输出明确参数错误。
- `src/tun_device.cpp`：在 OS 设备访问边界也拒绝超长名称，返回 filename_too_long；校验后完整复制名称，删除静默截断。
  配置检查负责用户提示，设备边界检查负责直接调用该接口时的内存与名称约束；没有新增名称转换规则。
  空名称及内核返回实际名称的处理保持不变。

测试修改：

- `src/protocol_tests.cpp` 增加设备接口拒绝超长名称且未保留 fd 的无特权测试。
- 新增 `tests/interop/test_tun_names.py`：参数边界、真实设备创建、删除、进程退出和资源清理。
- 扩展 `run_transparent_interop.py`：worker 配置、双入口多目标、严格 payload/source 校验、会话/GlobalID 统计及真实空闲回收。
- 新增 `run_socks_connect_semantics.py`：八个正常/失败场景、时序观察、受控 DNS/目标失败及本地会话 fd 回收。
- CMake 注册新增用例；README、架构和兼容文档记录 TUN 名称及 SOCKS REP 语义。

没有增加全局会话管理器、锁、dispatcher、流迁移、生产超时配置、重试、重连或公共接口可见性。
没有修改 Vision、VLESS/REALITY 生产转发代码及既有支持边界。

## 5. RED / GREEN 与运行命令

最终构建命令：

```bash
cmake -S . -B /tmp/rv-review-20261106 \
  -DCMAKE_BUILD_TYPE=Debug \
  -DRV_XRAY_EXECUTABLE=/tmp/rv-review-20261106/xray-a4a3dff \
  -DRV_ENABLE_PRIVILEGED_TESTS=ON
cmake --build /tmp/rv-review-20261106 -j4
```

完整 CTest 命令：

```bash
unshare -Urnm sh -c 'mount -t tmpfs none /run; ip link set lo up; env -u RV_TUN_INTEROP_NAMESPACE -u RV_TUN_NAMES_NAMESPACE -u RV_SOCKS_SEMANTICS_NAMESPACE ctest --test-dir /tmp/rv-review-20261106 -j4 --output-on-failure'
```

结果：**13/13 通过，148.57 秒**。M/final-ctest.log 保存完整结果。
测试格式整理前后 AST 相同；随后仅将 SOCKS 报告字段名称明确为“日志可见”，另执行定向 CTest，通过结果在 M/final-socks.log。

| 验证 | RED / 基线 | 最终结果 | 真实 Xray / Direct |
|---|---|---|---|
| Debug 构建 | 基线二进制留存 | 成功 | 不适用 |
| rv_protocol_tests（含设备接口边界） | 系统用例先观察截断 | PASS | 无 Xray；协议解析回归 |
| rv_help / rv_invalid_config / rv_unresolvable_server | 既有测试 | PASS | 无 Xray |
| rv_tun_reset_tests | 保留既有用例 | PASS | mock，不替代系统验收 |
| rv_tun_names | 16/42 字节名称创建截短设备，exit 非预期 | PASS：配置 exit=1、零设备；合法名称真实创建/删除 | 无 Xray，不涉及 Direct |
| rv_udp_workers_1/2/4 | 未复现多连接/错投；基线空闲重建也通过 | PASS | 真实 Xray，XUDP 不启用 Direct |
| rv_socks_connect_semantics | 八场景基线观察 | PASS / BY DESIGN | 真实 Xray；不以此用例证明 Direct |
| rv_xray_interop | 复用既有场景 | PASS | 真实 Xray；常规双向 Direct、分片 ServerHello uplink Direct、TLS 1.2 fallback 均保持 |
| rv_tun_interop | 复用既有场景 | PASS | 真实 Xray；IPv4/IPv6、XUDP、RST、设备生命周期 |
| rv_transparent_interop | 复用既有场景 | PASS | 真实 Xray；REDIRECT、TCP/UDP TPROXY、来源、边界、既有连接复用 |

UDP 单独对照命令（N=1/2/4，实际分别运行）：

```bash
unshare -Urnm sh -c 'mount -t tmpfs none /run; exec python3 tests/interop/run_transparent_interop.py run --xray /tmp/rv-review-20261106/xray-a4a3dff --client /tmp/rv-maintenance-20261106/baseline --work-dir /tmp/rv-maintenance-20261106/workers-N-idle --workers N --udp-worker-check --dual-ingress --idle-seconds 125'
```

最终客户端的每个 worker 用例也由完整 CTest 在新的 namespace 重复执行。完整记录含来源、worker/session ID、GlobalID 和发送/接收统计。

| workers | 来源 41001 的 worker | 来源 41002 的 worker | 首轮会话 | 空闲重建后累计会话 | payload | 旧 TCP 关闭 / ID 稳定 |
|---:|---:|---:|---:|---:|---|---|
| 1 | 0 | 0 | 2 | 4 | 192/192，无错误来源 | 是 / 是 |
| 2 | 0 | 1 | 2 | 4 | 192/192，无错误来源 | 是 / 是 |
| 4 | 2 | 0 | 2 | 4 | 192/192，无错误来源 | 是 / 是 |

两客户端来源始终各有一条活动会话和各自的 GlobalID；四条累计会话是每个客户端回收后各重建一次，并非同时四条。
GlobalID 的实际 8 字节值保存在 B/udp-workers-N/worker-summary.json；各客户端的 payload 及来源核对结果在 worker-client.log。

## 6. 协议回归与隔离

- 保持 Vision Direct、TLS 1.2 fallback、ServerHello 跨 record、XUDP、SOCKS 认证、嗅探及半关闭能力。
- TUN 名称成功/失败路径与真实设备删除通过，既有 TUN RST 和生命周期用例通过。
- 所有系统测试位于 user/network/mount namespace；新增第二入口沿用已有隔离拓扑的反向路径设置，没有修改宿主 sysctl。
- 没有增大队列、资源限制或修改生产 idle timeout。
- 最终测试前后宿主主路由表、规则和链路快照相同，证据为 M/network-before.json、M/network-after.json；宿主 ip netns list 为空。
- 每个 SOCKS 用例关闭后，本客户端 fd 从 7 恢复到 7，没有观察到客户端会话 fd 泄漏。

## 7. 遗留风险

- P3 / BY DESIGN：REP=0 不保证最终目标连通，失败可能随后 EOF；无响应目标的等待时间取决于空闲超时等既有机制。
- 无响应目标测试中，Xray 服务端在本客户端关闭后短时保留 CLOSE_WAIT（当时目标 dial 仍挂起）；
  原始状态已记录，测试结束停止 Xray 后释放。未测量其自然最终回收时间，不能据此认定永久泄漏，也不声称服务端立即回收。
- UDP 多 worker 结论限定本轮 Linux 内核、TPROXY 拓扑和负载；没有将未复现的假设改成确定性缺陷，也未声称覆盖所有内核或部署方式。

没有留下已确认而未修复的本项目 P1/P2 功能问题。

## 8. Git 状态与结论

修改均未暂存，初始没有待保留的其他修改；未提交、未推送、未部署。
`ruff check tests/interop`、`git diff --check` 通过。

| 项目 | 结论 |
|---|---|
| UDP TPROXY 多 worker | GO（已测范围，原假设 NOT REPRODUCED） |
| TUN 名称校验 | GO |
| SOCKS5 CONNECT 成功语义 | BY DESIGN |
| 整体正确性 | GO（上述固定版本及验收范围） |
