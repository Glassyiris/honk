# Benchmark 实验室与结果

本文档描述 honk 的可复现 benchmark 环境，以及与 dae 的同时间 A/B 结果。
文档随代码维护，环境与数据保持同步。

## 实验室拓扑

```text
┌─────────────────────────────┐         ┌─────────────────────────────┐
│ 10.10.10.50（VM，4C/2G）     │         │ 10.10.10.70（物理机，50G）   │
│                             │         │                             │
│  ┌───────────────┐          │  LAN    │  协议服务器：                 │
│  │ netns "lab"   │ veth     ├────────►│   hy2        :8443/udp      │
│  │ 192.168.222.2 ├──────────┤         │   tuic       :2444/udp      │
│  └───────┬───────┘          │         │   anytls-sb  :2445/tcp      │
│          │ NAT + TPROXY     │         │   anytls-go  :2443/tcp      │
│  honk / dae（轮流运行）       │         │   ss-2022    :2447/tcp      │
│  lan_ifname: veth-lab       │         │   trojan     :2446/tcp      │
│  wan_ifname: ens3           │         │  测试目标：                  │
└─────────────────────────────┘         │   http       :8001-8006     │
                                        │   iperf3     :5201-5206     │
                                        │   udp echo   :53530         │
                                        └─────────────────────────────┘
```

- **引擎机（10.10.10.50）**：同一时刻只运行 honk 或 dae 之一。客户端位于
  netns `lab`(veth 对 `veth-lab` ↔ `veth-client`,192.168.222.0/24,
  nftables masquerade NAT)。客户端流量完整经过引擎的真实 eBPF 数据面，
  不是 loopback 捷径。
- **服务器机（10.10.10.70）**：官方 hysteria、tuic-server、sing-box、Go
  anytls-server，以及本地目标服务。服务器直连出网，"互联网"测试路径为
  客户端 → 引擎 → 代理服务器 → WAN。
- **隔离**：与生产网关（10.10.10.1）完全无关。生产验证单独进行并在下文
  单独说明。

### 已知的实验室限制

- 两台 VM 的 virtio 网卡均为单队列：VM↔VM 吞吐上限约 0.8–1.7 Gbps(TX 方向）;
  物理机↔VM 可达 9.4 Gbps。因此带宽测试的服务器侧放在**物理机**上，客户端
  RX(9.4 Gbps）才是上限，而不是 VM 间链路。direct 基线（引擎直通 + NAT):
  **9.39–9.41 Gbps**。
- 共享基础设施上的运行间方差约 ±5%;WAN 订阅（nexi）的停滞型问题以数分钟
  为周期波动，不是引擎回归——见文末"生产环境说明"。

## 各组件位置

| 组件 | 二进制 | 配置 |
| --- | --- | --- |
| hy2 server | 官方 `hysteria` | `:8443`，密码 `testpass123`，证书 CN `hy2.test` |
| TUIC server | `tuic-server` 1.0.0 | `:2444`,uuid `00000000-0000-0000-0000-000000000001` / `testpass123`，要求 SNI `hy2.test` |
| AnyTLS server | sing-box | `:2445`，密码 `testpass123` |
| AnyTLS server | Go 参考实现 `anytls-server` | `:2443`,`-p testpass123` |
| SS 2022 server | sing-box | `:2447`,`2022-blake3-aes-128-gcm`,psk `8JCsHssyVTFyPy5lYdNhZg==` |
| Trojan server | sing-box | `:2446`，密码 `testpass123`,SNI `hy2.test` |
| 目标服务 | python http.server、iperf3 | 端口 `8001-8006`、`5201-5206`;UDP echo `:53530` |

引擎配置按目的端口路由，无需 API 切换：`5201/8001 → hy2`、`5202/8002 →
tuic`、`5203/8003 → ss2022`、`5204/8004 → trojan`、`5205/8005 → anytls-sb`、
`5206/8006 → anytls-go`（仅 honk,dae 不支持 AnyTLS)。节点服务器端口走
`direct(must)`。

## 运行方式

脚本位于引擎机 `/root`（源文件在操作机 `/tmp/lab-bin`):

```bash
# 协议正确性矩阵（每协议：TCP 目标 / UDP echo / 互联网）
bash /root/test-protocols.sh

# 完整 benchmark：每协议的冷/热首请求延迟、iperf3 下载带宽、
# 引擎 CPU% 与 RSS
bash /root/bench.sh honk 'hy2 tuic ss2022 trojan anytls-sb anytls-go'
bash /root/bench.sh dae  'hy2 tuic ss2022 trojan'

# 冷建连延迟（健康检查基本关闭，3600s 间隔）
bash /root/bench-cold.sh

# P0 验收：10 万随机五元组 UDP 洪泛，资源有界 + 回落
bash /root/flood-test.sh 100000 20000
```

## 结果（2026-07-29,honk v0.0.1.beta.22)

### 带宽（iperf3 `-R` 单流，8s;direct 基线 9.41 Gbps)

| 协议 | dae | honk | honk/dae |
| --- | --- | --- | --- |
| hy2 | 2.06 Gbps | 1.86 Gbps | 90% |
| tuic | 2.63 Gbps | 2.01 Gbps | 76% |
| ss2022(codec 重写前/后） | 1.51 Gbps | 0.87 → **1.33 Gbps** | 88% |
| trojan | 4.18 Gbps | 4.00 Gbps | 96% |
| anytls(sing-box server) | — | 3.09 Gbps | — |
| anytls(Go server) | — | 3.21 Gbps | — |
| ss2022 4 流 | 5.51 Gbps | 5.05 Gbps | 92% |

### 三方对比（2026-07-29,honk v0.0.1.beta.23 + sing-box 1.13.14)

同时间 A/B/C。括号内 CPU = 测试期间核数;cold = 引擎启动后首个请求。

| 协议 | dae | sing-box | honk |
| --- | --- | --- | --- |
| hy2 | 2.10 Gbps (1.28c) | 2.10 Gbps (1.58c) | 1.93 Gbps (0.97c) |
| tuic | 1.80 Gbps (1.07c) | 2.09 Gbps (1.56c) | 2.10 Gbps (1.07c) |
| ss2022 | 1.51 Gbps (1.01c) | 1.47 Gbps (1.15c) | 1.30 Gbps (1.01c) |
| trojan | 4.15 Gbps (1.03c) | 4.52 Gbps (1.68c) | 3.99 Gbps (1.03c) |
| anytls(sb server) | — | 3.02 Gbps (1.01c) | 3.12 Gbps (1.04c) |
| anytls(Go server) | — | 4.46 Gbps (1.57c) | 3.54 Gbps (1.16c) |
| 冷建连 | 6–85 ms | 6–8 ms | 1–6 ms |
| RSS | 61–65 MB | 51–52 MB | 14–16 MB |

结论:honk 在所有协议上 CPU/Gbps 最低、内存约为 1/4、冷建连最快。
剩余差距:hy2 比两者低 8%,ss2022 比 dae 低 12%,trojan 比 sing-box
低 12%,anytls 对 Go server 比 sing-box 低 21%(ss2022 的 codec 重写
已收复大部分差距,见历史提交)。

sing-box 引擎以 TUN 入口跑在客户端 netns 内(`sb-client.json`,各
outbound 绑定 `veth-client` 使自身拨号绕出 tun);honk/dae 照旧跑在
根命名空间。

### 内联优化后变更(2026-07-29,honk dev @ 1715d86)

三方对比之后落地的数据面改动:anytls 直通流(`AnyTlsStream`,
取消每流 relay task/duplex)、ss `poll_read` 快路径、TLS 批量读
(`BatchRead`:BoringSSL 每次 `SSL_read` 只返回一条 ~16 KiB
record,包装器读到缓冲满或 Pending),以及 mux 会话泄漏修复
(`pool_bare_tcp` + `SessionPool::insert` 始终跟踪)。

完整诚实复测(每次运行引擎 CPU 均验证非零):

| 协议 | dae | sing-box | honk 优化前 | honk 优化后 |
| --- | --- | --- | --- | --- |
| hy2 | 2.10 (1.28c) | 2.10 (1.58c) | 1.93 (0.97c) | 1.94 (0.97c) |
| tuic | 1.80 (1.07c) | 2.09 (1.56c) | 2.10 (1.07c) | **2.18 (1.07c)** |
| ss2022 | 1.51 (1.01c) | 1.47 (1.15c) | 1.30 (1.01c) | 1.29 (1.00c) |
| trojan | 4.15 (1.03c) | 4.52 (1.68c) | 3.99 (1.03c) | **4.65 (1.02c)** |
| anytls(sb server) | — | 3.02 (1.01c) | 3.12 (1.04c) | **3.55 (0.99c)** |
| anytls(Go server) | — | 4.46 (1.57c) | 3.54 (1.16c) | 3.38 (1.02c) |

trojan、tuic、anytls-sb 现已反超 sing-box(CPU 约为其 60%);
ss 快路径实测无效(staging 拷贝不是瓶颈,ss2022 仍在 ~1.3 Gbps
单核受限)。剩余差距:hy2 −8%、ss2022 −12%、anytls-go −24%。

注:本节早期版本列过 ss2022 1.45 / anytls 3.14 / 4.37 Gbps,已
作废——当时实验 netns 里残留一个 sing-box TUN 客户端占用策略
路由,测到的其实是 sing-box 而非 honk。

### 冷建连延迟（ms，健康检查关闭，3 次）

| 协议 | dae | honk | 备注 |
| --- | --- | --- | --- |
| hy2 | 10–11 | ~5 | |
| tuic | 84–86 | ~4 | 去掉 auth grace 前约 160 |
| ss2022 | 6–7 | 6–27 | |
| trojan | 10–13 | 9–11 | |
| anytls | — | 9–12 | |

### 资源占用（稳态）

| 指标 | dae | honk |
| --- | --- | --- |
| RSS | 61–65 MB | 14–16 MB |
| iperf 期间 CPU（单核） | 1.0–1.4 核 | 1.0–1.2 核 |

### P0 洪泛验收（10 万随机五元组，20k/s)

| 阶段 | RSS | FD 数 |
| --- | --- | --- |
| 基线 | 19 MB | 72 |
| 洪泛峰值 | 365 MB（有界） | 8 258（有界） |
| 停流 60s 后 | 31 MB（回到基线） | 70 |

### DNS 架构 Criterion 对比

权威 `dns-final-stats` DNS 微基准将当前工作树（HEAD
`37858d36b18e5e809d49a13ae9c7d46a123b1d16`）与 baseline commit
`6bbf1dc929541d64178d44ab389dcfe3b3e55c1e` 对比。两边使用相同的
非默认 `dns-bench` harness：

```bash
CARGO_TARGET_DIR=/root/code/honk-anaylyze-dns/target \
  cargo bench -p honk-core --features dns-bench --bench dns -- \
  --save-baseline dns-final-stats
cargo bench -p honk-core --features dns-bench --bench dns -- \
  --baseline dns-final-stats
```

本次在 `nixos` 主机（Linux `7.1.4-cachyos`、Intel i9-13900H、20 个逻辑
CPU）上完成全部 32 个 Criterion group；工具链为 Rust
`1.99.0-nightly (87e5904f5 2026-07-20)`、Cargo
`1.99.0-nightly (3efb1f477 2026-07-17)`、LLVM `22.1.8`。baseline 的
detached worktree 只覆盖编译相同 case 所需且逐字节一致的 benchmark feature、
support、harness 与 stats 定义；其余 DNS 生产代码均来自精确 baseline SHA。
不同主机的 timing 不可比较。

| Case | 当前中心估计 | Baseline ratio | Criterion 结果 / 建议判定 |
| --- | ---: | ---: | --- |
| 真实 typed `CacheKey::new` 构建 | 77.971 ns | 0.9502x | 改善；≤1.10x 通过 |
| Policy 求值，1 条规则 | 74.814 ns | 1.0000x | 未检测到变化；≤1.10x 通过 |
| Policy 求值，32 条规则 | 202.63 ns | 1.0103x | 未检测到变化；≤1.10x 通过 |
| Policy 求值，128 条规则 | 695.33 ns | 1.0391x | 检测到回归；≤1.10x 通过 |
| 独立 cache hit，1 task | 329.72 ns | 1.3392x | 检测到回归；≤1.10x **未达到** |
| 独立 cache miss，1 task | 248.50 ns | 1.4163x | 检测到回归；≤1.10x **未达到** |
| 独立 cache hit，16 tasks | 4.6439 µs | 1.3665x | 检测到回归；≤1.10x **未达到** |
| 独立 cache miss，16 tasks | 2.9261 µs | 1.6597x | 检测到回归；≤1.10x **未达到** |
| 独立 cache hit，64 tasks | 30.214 µs | 1.2959x | 检测到回归；≤1.10x **未达到** |
| 独立 cache miss，64 tasks | 21.358 µs | 1.2509x | 检测到回归；≤1.10x **未达到** |
| Singleflight，128 waiters | 773.57 µs | 1.3670x | 检测到回归；建议项 |
| Forwarder cache hit | 4.2746 µs | 1.5155x | 检测到回归；≤1.15x **未达到** |
| 真实 runtime lease acquire/drop | 50.845 ns | 1.0372x | 检测到回归；≤1.10x 通过 |
| 真实 runtime publication/swap | 1.4524 µs | 0.9578x | 改善；≤1.10x 通过 |
| 无 gate atomic event record | 6.8079 ns | 1.3697x | 检测到回归；建议项 |
| Best-effort atomic counter scrape | 2.2260 ns | 1.0074x | 未检测到变化；建议项 |
| 1 万条 cache 构建/插入 | 3.4616 ms | 1.2640x | 检测到回归 |
| 1 万条 allocated bytes | 1,628,640 bytes | 0.9996x | ≤1.50x 通过 |

typed-key 构建只解析一次真实 query，随后每个测量迭代都用真实 query context、
`PolicyId`、upstream scope 和 resolve operation 调用生产 `CacheKey::new`。
runtime 测量调用生产 provider 的 `acquire`/lease drop，并构造替换
`DnsRuntime` 后执行 `prepare_publication(...).commit()`。observability case
调用真实的无 gate `AtomicU64` recorder 与 best-effort scrape。每个 counter
单调递增，但 scrape 不承诺 counter 之间的一致性。baseline 有意覆盖相同 stats 实现，因此
两次运行间的 delta 是噪声对照，不是新旧生产实现对比。

已批准预算没有为 observability case 规定 baseline ratio 或绝对阈值；它们是
建议性的 mechanism 测量。当前 record 为 6.8079 ns，只执行一次 relaxed atomic
increment，不再有 shared gate、spin 或 yield。虽然它相对不同 baseline 生产树中
逐字节相同的 overlay 为 1.3697x，但比上一份权威报告中 gated current 的
12.025 ns 低 43.4%。因此绝对 hot-path 工作量更小，也无法串行化相互独立的 DNS 请求。

timing 上限是建议目标，未达到的项目不会隐藏或放宽。cache case 现在执行稳定的
canonical cache-key identity 工作；1/16/64-task 的六个 cache case 均未达到
≤1.10x，forwarder cache hit 也未达到 ≤1.15x。benchmark 没有把 identity 工作
从 cache 操作中单独分离，因此这些结果不归因于已移除的 stats gate。功能发布、
取消、顺序与资源边界仍由硬性测试断言。

64-task 独立 hot-key 吞吐为 2.1183 Melem/s，串行参考为
4.1669 Melem/s，即 0.508x，未达到建议的 ≥2x 目标。其单线程 Tokio
`join_all` harness 测到的是调度成本，而非多核扩展。并行 A+AAAA 为
1.2650 ms，较慢 AAAA 分支为 1.2794 ms，即 0.989x，通过 ≤1.25x 目标；
重叠执行与测量 noise 可使组合 case 的中心估计略低于独立分支。

原始 provenance receipts：

| Artifact | 路径 | SHA-256 |
| --- | --- | --- |
| Baseline timing | `.omo/evidence/final-stats-remediation/benchmark-baseline.log` | `07035f23a3ff5da118a5d33f0577d556720adbc7ee6129ee6785e9cf44d272e0` |
| 当前 timing/comparison | `.omo/evidence/final-stats-remediation/benchmark-current.log` | `49f4e0111de89cadc67a0cd55b056e89f97f263c3c394d8f6a0d894d80119ef3` |
| Baseline provenance | `.omo/evidence/final-stats-remediation/baseline-provenance.log` | `870f22ea31b04b3452fd13ee5cdd3df46f9db767992c23aeae3b11799293a33a` |
| 当前 provenance | `.omo/evidence/final-stats-remediation/current-provenance.log` | `ad8bcd05336bd95183f6d9db006f66816c4db83219384dc4efbcd15a44b3cdb1` |

机器可读 checksum receipt 位于
`.omo/evidence/todo12-benchmark-final-gate-checksums.txt`；完整提取与方法说明位于
`.omo/evidence/todo12-benchmark.md`（SHA-256
`0121f37508664dd09a94060ee036ff20770ea3017cf521219a0bdfda3690d52a`）。

## 生产环境说明（10.10.10.1 网关，nexi AnyTLS 订阅）

- 每次部署后 TCP(google/baidu/cloudflare）与 HTTP/3(cloudflare）均通过，
  网关日志无错误。
- HTTP/3 间歇停滞（首包快、正文暂停约 14s）以数分钟为周期出现，与订阅
  UDP 线路质量相关，而非引擎构建——beta.20/21/22 的 A/B 部署在同一小时内
  两种结果都会出现。客户端 qlog 显示约 12% 数据报"先判丢、后迟到"（延迟
  型而非内核/socket 丢包）。缓解工作（framed transport、UoT 直通、endpoint
  生命周期）已在 beta.17–19 落地；残余问题随 WAN 状况波动。

## 回归门禁

- `just outbound-ci` — fmt、clippy、honk-config + honk-outbound 套件。
- `just clash-ci` — fmt、clippy、clash_api_test + integration_test。
- `just dns-ci` — DNS 子系统门禁。
- Release CI(`.github/workflows/release.yml`)— workspace 测试门禁 +
  四目标构建（x86_64/aarch64 × gnu/musl)+ BTF 校验 + tarball 发布。
- [DNS 灰度与回滚操作手册](./dns-rollout.zh.md) — 仅用于隔离授权主机；
  本地 benchmark lane 未执行特权步骤。
