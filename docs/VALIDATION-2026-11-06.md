# REALITY / Vision 修复验收（2026-11-06）

## 1. 本地基线

- 仓库：`/home/gyl/example/reality_vision`，分支 `main`。
- HEAD：`87298781322653dd481595d8ad69b3606cade37c`。
- 开始时工作区、暂存区均为空；本轮未提交、未推送。
- Linux `6.8.0-138-generic`，GCC `16.2.0`，CMake `3.31.10`，Go `1.27.3`。
- 当前用户 uid 1000；`unshare -Urnm` 可用，在独立 user/network/mount namespace 内取得测试所需权限。
- 构建及证据目录：`/tmp/rv-review-20261106`（下文记为 B）。

固定 Xray 源码位于 `/home/gyl/data/code/Xray-core`，完整提交为
`a4a3dff5b20c2faae567b742c172c7b95e75c083`，tracked 文件无修改。
其中有用户原有的未跟踪调试二进制，未更改。目录原有 `xray` 为 24.9.7，没有用作最终验收对象。

实际构建命令：

```bash
cd /home/gyl/data/code/Xray-core
go build -buildvcs=false -o /tmp/rv-review-20261106/xray-a4a3dff ./main
```

`xray-a4a3dff version` 输出 `Xray 26.10.31 Custom (go1.27.3 linux/amd64)`。
`-buildvcs=false` 不嵌入工作目录的 dirty 标志；源码 SHA 在本记录中单独固定。

| 最终二进制 | SHA-256 |
|---|---|
| B/xray-a4a3dff | `f407ab1a09330c4400b41f6a7516e74f3c6adf4e3ffd0f65a335e8472c2bf1bd` |
| B/reality_vision（Debug） | `48f252f0c41a0f6d15b26479545d91e9996c0ddfbfe6b8bb378c6bf013e30dd0` |
| B/reality_vision-baseline（修复前） | `51bae2da72310206ce02a24baf4967c452ba8ac8f50d11b6e4a4e6f581f82c70` |

## 2. 问题核实

| 问题 | 状态 | 证据 |
|---|---|---|
| ServerHello 跨 record 提前结束识别 | CONFIRMED → FIXED | 新单元测试先失败；四-record 真实 TLS 用例修复前没有 uplink Direct，修复后出现 command=2 和 TX raw |
| TUN 连接阶段收到 RST 时误报 | CONFIRMED → FIXED | mock 判定测试修复前有两个错误，修复后连接/读取阶段与失败路径均通过 |
| TUN 测试缺少显式 namespace 清理验证 | FIXED | 成功创建的 namespace 登记到现有 finally；断言失败与 SIGKILL 探针验证清理 |
| 透明测试受继承的 src_valid_mark 影响 | CONFIRMED → FIXED（测试设置） | 基线和修复后二进制均 TCP TPROXY 超时；显式关闭测试 namespace 的 src_valid_mark 后完整场景通过 |
| 四-record 用例的 Xray downlink fallback | BY DESIGN（固定对照实现边界） | Xray 日志把分片 ServerHello 判为 TLS 1.2；客户端 RX command=1，真实 TLS/HTTP 仍成功 |
| P-256 / 外层 HRR / KeyUpdate 等文档边界 | BY DESIGN | 本轮未扩展 |

## 3. 修复说明

- `src/vision_codec.{hpp,cpp}`：沿用 `done_`；新增 Handshake 副本和累计观察字节计数。
  record 长度只控制 record 消费，Handshake 类型和 24 位长度控制 ServerHello 完成。
  record payload 与重组消息各最多 16 KiB，record header 另计；累计观察最多 64 KiB。
  非法续接、超限及不支持消息不启用 Direct。识别函数不等待网络，也不替换任何原始网络数据。
- `src/protocol_tests.cpp`：对全部两-record Handshake 切点及全部两次 TCP 读取切点组合测试；
  另覆盖逐字节 record/TCP、同批多 record、后续数据、截断、非法长度、不支持消息及累计限制。
- `tests/interop/run_xray_interop.py`：仅在受控测试中重新分片 OpenSSL 的 ServerHello；
  四条 record 的 payload 拼接必须等于原 payload，后续数据按原顺序转发。
  内层实际 TLS 握手及 HTTP 往返必须成功，并断言客户端允许 Direct、command=2、TX raw。
  使用完整测试日志作断言，避免新增用例后 tail 截断早期用例的证据。
- `tests/interop/run_tun_interop.py`：连接阶段只接受 ECONNRESET/ECONNREFUSED，读取阶段只接受 ECONNRESET。
  EOF、普通数据、超时、不可达和权限错误不算通过。
  `ExitStack` 复用 finally 清理流程，确保一项清理检查失败后仍处理其他资源。
  只清理成功创建的测试 namespace，并验证 TUN 消失及 namespace 删除。
  补充 SIGTERM 与 SIGKILL 后非持久 TUN 自动消失的检查。
- `tests/interop/test_tun_interop.py` 和 CMake：注册 7 项无网络依赖的判定/清理单测。
- `tests/interop/run_transparent_interop.py`：在自建代理 namespace 中把 all/入口接口的
  `src_valid_mark` 设为 0。该拓扑的 mark 用于 TPROXY 本地投递，不用于反向路径验证。
  未更改宿主参数或生产转发代码。单独调整入口接口 rp_filter 的尝试未解决问题，已撤回。
- 兼容及架构文档同步记录识别限制和四-record 用例的单向 Direct 边界。

没有修改 `vision_stream.cpp`、REALITY record 转发、TUN 生产实现，没有新增公共接口、生命周期布尔状态、重连或协议能力。

## 4. RED / GREEN

所有命令在仓库目录执行，B 替换为上述绝对路径。

| 命令/对象 | RED | GREEN | 证据 |
|---|---|---|---|
| `B/reality_vision --self_test`（先仅添加回归，再修生产） | exit 1：`Vision missed ServerHello split across TLS records` | exit 0，最终 CTest 通过 | B/red-unit.log、B/final-ctest.log |
| `python3 tests/interop/test_tun_interop.py` | 6 个测试中两个连接阶段用例异常逃出 | 扩充后 7 个测试通过 | B/red-tun-unit.log、B/final-tun-unit.log |
| `python3 tests/interop/run_xray_interop.py --xray B/xray --client B/reality_vision-baseline --work-dir B/red-interop` | HTTP 传输成功，但四-record 用例缺少 Direct 三项标记，exit 1 | 最终固定 Xray 互通测试通过 | B/red-interop.log、B/xray-interop/vision-socks.log |
| 透明代理脚本，基线二进制及默认测试配置 | TCP TPROXY connect 超时 | 修正测试 namespace 的 src_valid_mark 后通过 | B/baseline-transparent.log、B/transparent-diagnostic.log、B/final-ctest.log |

RED 的 B/xray 是上一轮在同一固定源码提交上构建的 26.10.31；最终全部验收统一使用重新构建并校验的 B/xray-a4a3dff。
RED 日志保留原始失败，包括当时日志 tail 截断带来的早期 fallback 标记缺失；跨 record 缺陷另有完整会话日志和单元测试失败佐证。

## 5. 协议互通

实际运行的构建和最终测试命令：

```bash
cmake -S . -B /tmp/rv-review-20261106 \
  -DCMAKE_BUILD_TYPE=Debug \
  -DRV_XRAY_EXECUTABLE=/tmp/rv-review-20261106/xray-a4a3dff \
  -DRV_ENABLE_PRIVILEGED_TESTS=ON
cmake --build /tmp/rv-review-20261106 -j4
unshare -Urnm sh -c 'mount -t tmpfs none /run; ip link set lo up; env -u RV_TUN_INTEROP_NAMESPACE ctest --test-dir /tmp/rv-review-20261106 --output-on-failure'
```

结果：Debug 构建成功，最终 CTest **8/8 通过**（22.98 秒）。

| CTest / 场景 | 结果 | 真实 Xray | Direct 验证 |
|---|---|---|---|
| rv_protocol_tests：基础协议、跨 record 回归及失败路径 | PASS | 否 | 识别结果，非网络模式切换 |
| rv_help / rv_invalid_config / rv_unresolvable_server | PASS | 否 | 不适用 |
| rv_tun_reset_tests：7 项 Python 判定/清理单测 | PASS | 否 | 不适用 |
| rv_xray_interop：普通 TCP | PASS | 是 | command=1，禁止 raw |
| rv_xray_interop：TLS 1.2 | PASS | 是 | fallback，禁止 raw；Xray splice 数未增长 |
| rv_xray_interop：常规 TLS 1.3 / SNI 嗅探 | PASS | 是 | TX command=2、TX raw、RX Direct，双向验证 |
| rv_xray_interop：四-record ServerHello | PASS | 是 | parser 识别 → command=2 → TX raw → 真实 TLS/HTTP 成功；RX 为 fallback |
| rv_xray_interop：XUDP、IPv4/IPv6/域名、多目标复用、7526/7527 bytes、UDP/443 | PASS | 是 | UDP 不进入 Direct |
| rv_xray_interop：认证、无认证、错误凭据、TCP 半关闭、TX Direct/RX TLS 关闭 | PASS | 是 | 各自既有断言通过 |
| rv_tun_interop | PASS | 是 | TCP/UDP echo 与生命周期验证，不宣称 TUN TLS Direct |
| rv_transparent_interop | PASS | 是 | TCP REDIRECT、TCP/UDP TPROXY、UDP 边界、源地址/53 端口及已有 XUDP 连接复用；不宣称 TLS Direct |

解析器正确识别、Vision 选择 Direct、真实 TLS 应用传输成功、真实 Xray 互通，分别由不同层次的断言支撑；没有用单元测试替代网络验收。

## 6. 系统级验收

TUN 最终测试验证 IPv4/IPv6 TCP、HTTP Host 嗅探、idle timeout、UDP 多目标及边界；上游停机后读取阶段收到实际 RST。
移除测试设备后客户端进程退出；重新启动后分别验证 SIGTERM 和 SIGKILL 使非持久 TUN 消失。
所有 namespace 创建、地址/路由/防火墙配置均位于隔离环境。

额外执行的失败清理探针：

```bash
unshare -Urnm python3 /tmp/rv-review-20261106/probe_tun_cleanup.py
```

该脚本调用真实 TUN 测试，分别在 TUN 创建并配置后注入断言失败、杀死代理再注入失败。
两次都确认所有登记子进程退出、`ip netns list` 为空、父测试 namespace 中没有 rv-tun/rvtp/rvtx。
不是用 mock 代替真实设备清理；证据位于 B/cleanup-probe.log。

透明代理最初的失败发生于隔离 network namespace，未通过 sudo 修改宿主配置。
修正测试拓扑参数后完整回归通过，不再有权限阻塞项。
最终测试前后宿主 IPv4/IPv6 路由、规则及链路配置快照相同，当前进程仍位于原 network namespace
`net:[4026531840]`；宿主 `ip netns list` 为空。
快照位于 B/host-network-before.json 和 B/host-network-after.json。
未执行宿主默认路由或防火墙修改，也未访问或删除用户原有 TUN。

## 7. 遗留风险

- P3 / BY DESIGN：固定 Xray 的 ServerHello 检测在该跨 record 构造下不启用 downlink Direct。
  本客户端 uplink Direct、内层真实 TLS/HTTP 仍通过；本轮不修改第三方 Xray。
- 超过 16 KiB 的重组 ServerHello 或超过 64 KiB 的累计识别输入回退，不扩展支持边界。
- 本次是固定版本、本地受控环境回归，不代表跨版本、长时间压力或公网网络验收。

没有留下已确认而未修复的本轮 P1/P2 问题。

## 8. 工作区状态与结论

所有修改未暂存，暂存区为空，未提交、未推送。
执行 `ruff check tests/interop`、`git diff --check` 均通过。
生产修改仅限 Vision ServerHello 识别；其他修改为测试、CMake 测试注册及文档。

| 验收对象 | 结论 |
|---|---|
| REALITY/Vision 客户端协议互通 | GO（上述固定版本及范围） |
| ServerHello 跨 record | GO |
| TUN | GO |
| 透明代理 | GO |
| 整体 | GO |
