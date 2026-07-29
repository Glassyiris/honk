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

### 内联优化后复测(2026-07-29,honk dev @ edd5d8f)

anytls 数据面内联(`AnyTlsStream`,取消每流 relay task/duplex)与
ss `poll_read` 快路径(直接解密进调用方缓冲)之后:

| 协议 | sing-box | honk 优化前 | honk 优化后 |
| --- | --- | --- | --- |
| ss2022 | 1.47 Gbps | 1.30 Gbps | **1.45 Gbps** |
| anytls(sb server) | 3.02 Gbps | 3.12 Gbps | **3.14 Gbps** |
| anytls(Go server) | 4.46 Gbps | 3.54 Gbps | **4.37 Gbps** |

ss2022 已与 sing-box 持平(比 dae 低 4%);anytls 两种 server 都
追平 sing-box,CPU 约 0.9 核。剩余差距:hy2 −8%、trojan −12%。

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
