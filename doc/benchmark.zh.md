# Benchmark 实验环境与结果

本文档记录 honk 可复现的 benchmark 环境，以及与
[dae](https://github.com/daeuniverse/dae)、[sing-box](https://github.com/SagerNet/sing-box)
的同机 A/B/C 结果。历史结果保留当时的二进制和服务端配置，最新一轮排在最前。

## 实验拓扑

```text
┌──────────────────────────────────────┐       ┌─────────────────────────────┐
│ 引擎机(每轮选择一台)                  │       │ 10.10.10.70(物理机,50G)     │
│                                      │       │                             │
│ x86: 10.10.10.49,4 vCPU / 2 GiB     │  LAN  │ 协议服务端:                 │
│ ARM: 10.10.10.118,R2S / 1 GiB        ├──────►│  hy2/tuic/SS/Trojan/AnyTLS │
│                                      │       │ 目标服务:                   │
│  ┌───────────────┐                   │       │  HTTP  :8001-8006,8080      │
│  │ netns "lab"   │ veth              │       │  iperf:5201-5206,5300      │
│  │ 192.168.222.2 ├──► 真实 eBPF 路径 │       │  UDP echo:53531-53536      │
│  └───────────────┘                   │       └─────────────────────────────┘
│ honk / dae(同一时刻只跑一个)          │
│ LAN: veth-lab                        │
│ WAN: ens3(x86) / USB GbE(ARM)        │
└──────────────────────────────────────┘
```

- **x86 引擎机(`10.10.10.49`)**:Arch Linux VM，内核 `7.2.3-arch1-3`，4 个 host-passthrough
  i5-13600K vCPU、2 GiB RAM,WAN 为 `ens3`。客户端在 network namespace
  `lab` 中(`veth-lab` ↔ `veth-client`,192.168.222.0/24,nftables
  masquerade),direct 对照约 9.4 Gbps。
- **ARM 引擎机(`10.10.10.118`)**:NanoPi R2S,RK3328 四核 Cortex-A53,
  可用内存 968 MiB,WAN 为 `eth0`。使用相同 `lab` netns 拓扑,direct 对照
  约 0.8–0.9 Gbps。
- **真实数据面**:同一时刻只运行一个引擎。honk 和 dae 经真实 eBPF/TPROXY
  截获 client netns 流量；sing-box 在该 netns 内运行 `mixed` TUN stack。
  三组均经物理 LAN 到达 `.70`，比较的是完整配置栈，不是完全相同的截获实现。
- **服务端(`10.10.10.70`)**:本轮使用 sing-box 1.14.3 和官方 anytls-go 0.0.13，
  配合本地 HTTP/UDP/iperf3 targets。历史各轮的服务端版本见对应日期章节。
- **隔离**:这里的一切不触碰生产网关(`10.10.10.1`)；生产验证另行标注。

### 已知的实验室限制

- 不对跨架构绝对吞吐作归一化:`.49` 是虚拟多千兆路径,`.118` 同时受 USB
  GbE 和 A53 CPU 限制。公平结论必须比较**同一机器**上的 honk-vs-dae；
  两台机器用于判断结论能否跨架构复现。
- loaded-latency 阶段会在同一路由上同时跑一条 reverse iperf3。尾延迟包含
  engine scheduling、crypto、softirq 竞争和 NIC 上限,不是空载网络 RTT。
- 共享基础设施的轮间方差约 ±5%。其他会话若中途重启引擎或在 ARM 板编译,
  该 arm 即失效,发布前必须重跑。
- x86 VM 使用 host CPU 透传(AES-NI + AVX2)。下文无 SIMD 的旧 qemu64
  数字只保留为明确标日期的历史,不是当前 x86 基线。
- 历史 rprx 行缺少可读取的服务端 process/version 身份；其客户端 wire 参数和
  binary hash 仍保留，但不能作为服务端版本回归基线。
- 2026-08-08 代理矩阵覆盖当时已配置的全部 endpoint：HY2、TUIC、SS2022、
  Trojan、两个 AnyTLS server、VLESS Vision/REALITY 与 VMess。当前仍无
  SOCKS5 endpoint。Juicity 未进入该矩阵；下文补充 2026-08-26 针对现有 Go
  server 的专用对比。较早的 Juicity direct-UDP 卸载结果不是代理对比。
- REALITY fixture 需要一个本机确实可达的 `dest`。若 `dest` 的 A 记录部分
  不可达（`.70` 上的历史 `dl.google.com`），每次未认证 fallback 都会卡
  5 秒并令握手失败；已认证 client 一旦需要 fallback 也会失败。2026-10-24
  轮改用 `www.microsoft.com:443`。

## 服务端 fixtures

| 组件 | 二进制 | 配置 |
| --- | --- | --- |
| hy2 server | sing-box 1.14.3 | `:8443`,密码 `testpass123`,证书 CN `hy2.test` |
| TUIC server | sing-box 1.14.3 | `:2444`,uuid `00000000-0000-0000-0000-000000000001` / `testpass123`,要求 SNI `hy2.test` |
| Juicity server | 官方 Go `juicity-server` v0.4.3 | `:2451`,uuid `00000000-0000-0000-0000-000000000001` / `testpass123`,SNI `hy2.test`,`congestion_control: bbr` |
| VLESS REALITY + Vision | sing-box 1.14.3 | `:8443`,uuid `4a3d42a2-a62d-4454-b2a2-7cbe5ddf4c7a`,flow `xtls-rprx-vision`,REALITY `dest www.microsoft.com:443`,short id `a1b2c3d4e5f60718` |
| VLESS REALITY | sing-box 1.14.3 | `:8444`,同一 uuid、无 flow,REALITY 参数相同 |
| VMess server | sing-box 1.14.3 | `:8446` TCP,uuid `82166345-d1bb-48f8-bd3b-cf0c152a863c`(`:8445` VMess/WS+TLS 已配置但未使用) |
| AnyTLS server | sing-box 1.14.3 | `:2445`,密码 `testpass123` |
| AnyTLS server | 官方 anytls-go 0.0.13 | `:2443`,`-p testpass123` |
| SS 2022 server | sing-box 1.14.3 | `:2447`,`2022-blake3-aes-128-gcm`,psk `8JCsHssyVTFyPy5lYdNhZg==` |
| Trojan server | sing-box 1.14.3 | `:2446`,密码 `testpass123`,SNI `hy2.test` |
| 目标服务 | Python HTTP/UDP fixture、iperf3 3.21 | HTTP `8001-8006` + `8080`、iperf3 `5201-5206` + `5300`、UDP echo `53531-53536`、本地 probe DNS `53539` |

常规引擎配置按目标端口路由,无需 API 切换：`5201/8001 → hy2`、
`5202/8002 → tuic`、`5203/8003 → ss2022`、`5204/8004 → trojan`、
`5205/8005 → anytls-sb`、`5206/8006 → anytls-go`。专用 rprx 配置
（honk、dae、sing-box）通过 harness index override 把 VLESS
Vision/REALITY/VMess 复用到在线目标槽 1–3；专用 Juicity 配置复用槽 1
完成 honk/dae 配对（sing-box 没有 Juicity outbound）。当前上游 dae 支持
完整六协议矩阵；历史 ARM 对照使用四协议共有面。节点服务端口为
`direct(must)`，未匹配的目的地回落 direct。每个客户端配置（包括 sing-box）
都必须显式路由 UDP echo 端口。rprx inbounds 与 HY2 共用 8443，因此两轮
之间 fixture 会切换 `singbox-server.json` 与 `singbox-rprx.json`。

## 方法学

统一 harness——`bench/lab-bench.sh`(在本仓库,于引擎机上运行)——
取代了旧的 bench.sh / bench-cold.sh / bench-cpu.sh / bench-honest.sh
四个脚本。用法和实验室要求见 `bench/README.md`。

每个 引擎 × 协议 测量:

- **cold**——每次重新启动引擎并经过 driver readiness 等待后的首个 HTTP 请求，
  3 次取中位数。3600s 间隔限制周期探测，但启动探测和连接池可能已完成预热；
  这不是保证物理 TLS/QUIC 握手全冷的测量。
- **hot p50/p95**——对每协议 HTTP 目标连发 15 个请求的开流延迟(代理会话已
  热)。QUIC 协议这项主要由连接/会话恢复决定,mux 协议由池化会话决定。
  常规 HTTP 样本必须得到成功的 2xx/3xx；连接或 status 失败会把该行标为
  invalid,不会把 curl 的失败耗时当成延迟。
- **bw**——iperf3 `-R` 下载,单流,3 次取接收端中位数。
- **udp**——每协议:echo RTT(对路由 echo 端口 5353x 发 15 个 ping 取
  中位数)和 iperf3 `-u -b 10G -l 1200 -R`(饱和供给下的接收带宽 +
  丢包率;数据报固定 1200B,因为 QUIC datagram 上限就在那附近)。
- **loaded 延迟稳定性**——常规吞吐测量之后,同一路由启动一条 reverse
  iperf3；有界 worker pool 按绝对 250ms deadline 打开 200 条独立 HTTP
  stream(共 50s),单次 timeout 不会串行阻塞后续样本。报告 p50/p95/p99、
  最大值、失败数与调度偏差；逐次结果保存为 JSONL,并保留对应 iperf3 JSON,
  避免把负载失败或压力不足误报成“稳定”。
- **cpu**——中位数带宽那一轮期间的引擎 CPU 核数
  (`/proc/<pid>/stat` utime+stime 差值除以 iperf3 传输窗口；若 client 在测试
  结束后仍挂住（如 dae 的 AnyTLS），墙钟分母会被虚增)。honk 的 pid 锚定
  clash API 监听者,停在单实例锁上的第二实例(零 CPU)不会污染指标。
- **rss**——带宽轮结束后的整数 MiB（`VmRSS / 1024`）。
- **direct 基线**——同样方法测量未代理路径(`8080`/`5300`)。

```bash
scp bench/lab-bench.sh bench/latency_stability.py root@10.10.10.49:/root/
ssh root@10.10.10.49 \
  "HONK_BIN=/root/honk-candidate bash /root/lab-bench.sh \
   'honk dae' 'hy2 tuic ss2022 trojan anytls-sb anytls-go'"

# ARM 使用其 dae 构建与 honk 共有的协议面。
scp bench/lab-bench.sh bench/latency_stability.py root@10.10.10.118:/root/
ssh root@10.10.10.118 \
  "HONK_BIN=/root/honk-candidate bash /root/lab-bench.sh \
   'honk dae' 'hy2 tuic ss2022 trojan'"
```

`lab-bench.sh` 记录 host/kernel 与三个二进制的 SHA-256。常规行追加到 `TSV`，
loaded summary 追加到 `STABILITY_TSV`；`STABILITY_DIR` 保留每一轮 TCP 带宽
JSON、UDP 带宽 JSON、loaded sample、summary 和 load JSON。collector fixture
用 `python3 bench/tests/latency_stability_test.py` 验证。

### VLESS Vision codec 候选基准

`crates/honk-outbound/benches/vless_vision.rs` 以明文 loopback 承载隔离响应
解码开销；生产 Vision 仍只允许 TLS/REALITY。两个用例都从确定性的
16 KiB 源写入中解码恰好 **16 MiB**，且每个二进制会在 Criterion 计时前
校验解码字节数：

- `vision_framed_16m`：多组 content/padding frame，最后为 `End`；
- `vision_direct_16m`：一个 `Direct` frame，随后为 raw tail。

配对的 release-musl 二进制仅在已确认的 x86-64 Debian 主机
`root@10.10.10.50` 上执行，并在同一 Criterion 目录中背靠背运行：

```bash
ssh root@10.10.10.50 \
  'mkdir -p /root/vless-vision-criterion && cd /root/vless-vision-criterion && \
   /root/vless-vision-bench.before --bench --save-baseline vless-before-final'
ssh root@10.10.10.50 \
  'cd /root/vless-vision-criterion && \
   /root/vless-vision-bench.after --bench --baseline vless-before-final'
```

候选仅在 framed 点估计改善、其 95% 区间排除超过 3% 的降速，且 Direct
点估计回退不超过 3% 时通过。

## 结果（2026-10-30，合并后的 `main` 在 canonical `.70` fixture 上的 A/B/C）

honk `v0.1.0-beta.3-13-gc8bfa7a3`（来自 `main` `c8bfa7a3`，静态 musl 构建并内嵌 eBPF 对象）对本仓库冻结的 upstream dae 与 sing-box 二进制，fixture 与 2026-10-24 相同。同一 harness、同一 `lab` namespace、同一 4 vCPU / 2 GiB engine host；二进制、配置、iperf3 原始 JSON 与稳定性样本见 `results/abc-2026-10-30-x86/`。

### 六协议轮：TCP 吞吐、进程 CPU 与 RSS

| engine | protocol | cold(s) | hot p50(s) | hot p95(s) | bw(Mbps) | cpu(cores) | rss(MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.001769 | - | - | 9403 | 0.00 | 67 |
| honk | hy2 | 0.002026 | 0.001160 | 0.001412 | 4550 | 0.47 | 75 |
| honk | tuic | 0.002303 | 0.001132 | 0.001415 | 3847 | 0.37 | 61 |
| honk | ss2022 | 0.001400 | 0.001109 | 0.001323 | 9391 | 0.34 | 75 |
| honk | trojan | 0.003263 | 0.000682 | 0.003749 | 9372 | 0.31 | 71 |
| honk | anytls-sb | 0.002976 | 0.001645 | 0.002219 | 9385 | 0.38 | 50 |
| honk | anytls-go | 0.003496 | 0.001615 | 0.003165 | 9379 | 0.40 | 63 |
| dae | direct | 0.002329 | - | - | 9396 | 0.00 | 46 |
| dae | hy2 | 0.009691 | 0.001493 | 0.002401 | 2736 | 0.58 | 58 |
| dae | tuic | 0.007977 | 0.001700 | 0.002242 | 3423 | 0.67 | 58 |
| dae | ss2022 | 0.003821 | 0.001657 | 0.002031 | 9392 | 0.37 | 59 |
| dae | trojan | 0.008111 | 0.005817 | 0.007399 | 9374 | 0.43 | 59 |
| dae | anytls-sb | 0.007265 | 0.000909 | 0.001209 | 9379 | 0.49 | 63 |
| dae | anytls-go | 0.007606 | 0.001614 | 0.002552 | 9372 | 0.49 | 61 |
| sing-box | direct | 0.002882 | - | - | 9408 | 0.37 | 62 |
| sing-box | hy2 | 0.008529 | 0.001719 | 0.002644 | 1975 | 0.53 | 67 |
| sing-box | tuic | 0.008670 | 0.001931 | 0.003128 | 3228 | 0.71 | 68 |
| sing-box | ss2022 | 0.003568 | 0.002061 | 0.003032 | 9402 | 0.49 | 65 |
| sing-box | trojan | 0.007664 | 0.006081 | 0.008469 | 9391 | 0.67 | 69 |
| sing-box | anytls-sb | 0.007950 | 0.001584 | 0.002485 | 9389 | 0.76 | 78 |
| sing-box | anytls-go | 0.007878 | 0.001613 | 0.002299 | 9370 | 0.92 | 78 |

### 六协议轮：UDP

| engine | protocol | echo RTT p50(s) | iperf3 -u -R (Mbps, loss) | cpu(cores) |
| --- | --- | --- | --- | --- |
| honk | hy2/udp | 0.000187 | 1036(84.6%) | 0.64 |
| honk | tuic/udp | 0.000158 | 1191(82.4%) | 0.65 |
| honk | ss2022/udp | 0.000119 | 2046(65.4%) | 0.73 |
| honk | trojan/udp | 0.000194 | 1705(75.6%) | 0.70 |
| honk | anytls-sb/udp | 0.000271 | 1671(74.2%) | 0.57 |
| honk | anytls-go/udp | 0.000410 | 1717(74.6%) | 0.59 |
| dae | hy2/udp | 0.000305 | 1179(82.9%) | 0.80 |
| dae | tuic/udp | 0.000397 | 1225(82.2%) | 0.82 |
| dae | ss2022/udp | 0.000216 | 2588(56.5%) | 1.24 |
| dae | trojan/udp | 0.000102 | 2908(56.6%) | 1.08 |
| dae | anytls-sb/udp | 0.000363 | 1746(72.9%) | 0.71 |
| dae | anytls-go/udp | 0.000410 | 1711(74.6%) | 0.70 |
| sing-box | hy2/udp | 0.000256 | 0(-) | 1.16 |
| sing-box | tuic/udp | 0.000126 | 1076(84.4%) | 1.43 |
| sing-box | ss2022/udp | 0.000334 | 2710(54.4%) | 1.38 |
| sing-box | trojan/udp | 0.000106 | 3794(41.6%) | 1.57 |
| sing-box | anytls-sb/udp | 0.000106 | 1406(77.4%) | 1.16 |
| sing-box | anytls-go/udp | 0.000108 | 1324(76.2%) | 1.10 |

### 六协议轮：负载下的延迟稳定性

| engine | protocol | load(Mbps) | p50(ms) | p95(ms) | p99(ms) | max(ms) | failures |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 9400 | 2.148 | 2.644 | 3.241 | 3.332 | 0/200 |
| honk | hy2 | 4000 | 1.427 | 1.711 | 3.896 | 4.606 | 0/200 |
| honk | tuic | 3970 | 1.394 | 1.713 | 2.117 | 4.746 | 0/200 |
| honk | ss2022 | 9397 | 2.258 | 3.288 | 4.950 | 6.008 | 0/200 |
| honk | trojan | 9388 | 1.833 | 2.598 | 2.826 | 4.610 | 0/200 |
| honk | anytls-sb | 9383 | 2.566 | 9.452 | 16.361 | 19.752 | 0/200 |
| honk | anytls-go | 9374 | 2.706 | 8.889 | 14.603 | 16.091 | 0/200 |
| dae | direct | 9402 | 3.097 | 3.780 | 4.629 | 1052.617 | 0/200 |
| dae | hy2 | 2806 | 1.797 | 2.242 | 3.243 | 4.493 | 2/200 |
| dae | tuic | 3442 | 1.805 | 2.176 | 2.857 | 3.799 | 0/200 |
| dae | ss2022 | 9394 | 3.518 | 9.227 | 15.493 | 17.798 | 0/200 |
| dae | trojan | 9365 | 5.738 | 12.367 | 18.518 | 21.713 | 0/200 |
| dae | anytls-sb | 9385 | 2.429 | 6.716 | 10.852 | 14.897 | 0/200 |
| dae | anytls-go | 9375 | 2.355 | 9.671 | 15.994 | 18.630 | 0/200 |
| sing-box | direct | 9410 | 3.313 | 4.051 | 4.227 | 4.472 | 0/200 |
| sing-box | hy2 | 2109 | 9.623 | 25.448 | 30.053 | 32.343 | 0/200 |
| sing-box | tuic | 3323 | 1.873 | 2.176 | 2.554 | 4.199 | 0/200 |
| sing-box | ss2022 | 9403 | 3.554 | 8.730 | 12.683 | 15.429 | 0/200 |
| sing-box | trojan | 9389 | 5.719 | 12.493 | 17.777 | 21.095 | 0/200 |
| sing-box | anytls-sb | 9384 | 2.523 | 7.130 | 13.681 | 16.895 | 0/200 |
| sing-box | anytls-go | 9362 | 2.460 | 8.043 | 12.958 | 18.578 | 0/200 |

### DNS Criterion 基准（`dns`，PR base `b724ee27` 对合并后的 main）

两侧均构建 `cargo bench -p honk-core --features dns-bench --bench dns`（head 来自合并后的 bench 分支 `f833538c`）；三次交替 baseline（`base1`、`head`、`base2`），100 samples、3 s warm-up、5 s measurement。完整 43 行表格见 `results/abc-2026-10-30-x86/dns-bench-aba.tsv`。

Both sides build `cargo bench -p honk-core --features dns-bench --bench dns` (head from the merged bench branch `f833538c`); three interleaved baselines (`base1`, `head`, `base2`), 100 samples, 3 s warm-up, 5 s measurement. Full 43-row table in `results/abc-2026-10-30-x86/dns-bench-aba.tsv`.

| benchmark | base1 | head | base2 | delta | drift | verdict |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `dns_observability/best_effort_snapshot` | 2.04 | 2.47 | 2.01 | +22.35% | 1.58% | REGRESSION |
| `dns_udp_validation_profile` | 29.85 | 31.85 | 29.96 | +6.49% | 0.38% | REGRESSION |
| `dns_forwarder_warmed/nxdomain_hit` | 770.53 | 790.10 | 773.57 | +2.34% | 0.39% | PASS |
| `dns_forwarder/cache_hit` | 815.44 | 827.15 | 812.73 | +1.61% | 0.33% | PASS |
| `dns_parallel_families/a_and_aaaa` | 1160442.80 | 1173502.14 | 1158492.20 | +1.21% | 0.17% | PASS |
| `dns_cache/get_hit` | 160.26 | 160.68 | 160.17 | +0.29% | 0.05% | PASS |
| `dns_forwarder_warmed/positive_hit` | 882.02 | 885.84 | 888.62 | +0.06% | 0.74% | PASS |
| `dns_observability/record_event` | 4.93 | 4.94 | 4.93 | +0.05% | 0.03% | PASS |
| `dns_cache_concurrency/read_write/1` | 48859.67 | 48683.25 | 48741.77 | -0.24% | 0.24% | PASS |
| `dns_cache_concurrency/same_shard/1` | 48324.18 | 48235.90 | 48700.73 | -0.57% | 0.78% | PASS |
| `dns_singleflight/128_waiters` | 199994.73 | 198177.32 | 200474.85 | -1.03% | 0.24% | PASS |
| `dns_cache/put` | 251.17 | 244.91 | 245.78 | -1.44% | 2.17% | PASS |

其中两行在 300 samples / 15 s 的确认轮（`dns-bench-confirmation.tsv`）中稳定复现：

- `dns_observability/best_effort_snapshot` +19.9%（2.08 → 2.50 ns）。该基准读取 DNS snapshot，而本次改动为其增加了五个准入/压力计数器，差值即新增的 atomic 读取（约 0.08 ns/个）。
- `dns_udp_validation_profile` +6.5%（29.9 → 31.8 ns）。`validate_exact_dns_query` 在两棵树中逐字节相同且不记录统计，因此这是 bench 二进制层面的 codegen 变化（内联/CGU 布局），不是该函数行为改变。base 树同源重建可稳定复现 29.9 ns，说明不是构建不确定性；如需追究，可按 2 ns 级微基准做定向 profile。

## 结果（2026-10-24，canonical `.70` fixture 全协议 A/B/C）

合并后的 `bench` 树（`20286c3d`，回合了 `origin/main` 的 `3d4825f6`：BBRv3
默认、QUIC 每次拨号独立 endpoint、AnyTLS 调优）跑在 canonical 拓扑上：
engine host `10.10.10.49`（Arch VM，4 vCPU，kernel `7.2.3-arch1-3`），client
位于 netns `lab`，经物理 LAN 到 `10.10.10.70`（20 vCPU，kernel
`7.2.7-cachyos`，已同步时钟）。同一时间只运行一个 engine。A/B/C = honk
`20286c3d`（静态 musl，`ebpf,native-api,clash-api,mimalloc,rprx`）对 dae
[v2.1.1](https://github.com/daeuniverse/dae/releases/tag/v2.1.1)（`dbae2e82`）
对 sing-box
[v1.14.3](https://github.com/SagerNet/sing-box/releases/tag/v1.14.3)
（`7054cac5`）。

三轮共用同一 harness、collector、目标（1,024 字节 HTTP body、iperf3 3.21、
UDP echo）与测量契约：

1. 六协议 `hy2 tuic ss2022 trojan anytls-sb anytls-go`，服务端为
   `singbox-server.json`（HY2/TUIC/SS2022/Trojan/AnyTLS）加 anytls-go
   0.0.13；
2. `vless-vision vless-reality vmess`，服务端为 `singbox-rprx.json`
   （8443 VLESS REALITY+`xtls-rprx-vision`，8444 VLESS REALITY，8446
   VMess/TCP），target slot 1–3 分别映射到三个代理；
3. `juicity`，服务端为 `:2451` 上的 juicity-server v0.4.3，仅 honk 与 dae
   （sing-box 没有 Juicity outbound）。

fixture 配置、`serve.sh standard|rprx` driver 与证书生成命令都在
[`abc-2026-10-24-x86/fixture`](../bench/results/abc-2026-10-24-x86/fixture/)；
完整调用见 `command-abc.txt`、`command-rprx.txt`、`command-juicity.txt`，
全部原始 TSV/JSONL/JSON 证据在同一
[campaign 目录](../bench/results/abc-2026-10-24-x86/) 下。

两个 fixture 事实影响复现：

- 当前 honk 拒绝与 node 同名的 group。因此 lab 配置统一使用
  `proxy-<protocol>` group（2026-10-11 的冻结配置本来也是如此）。
- REALITY 需要本机可达的 `dest`。本机上 `dl.google.com` 的部分 A 记录
  不可达（例如 `58.63.233.97`），每次未认证 REALITY fallback 都会卡 5 秒并
  令握手失败；即使认证本应成功，某些连接一旦需要 fallback 也会失败，并表现
  为 bulk 传输中断。本轮使用 `www.microsoft.com:443`（TLS 1.3 + h2）：
  smoke 与三轮测试都没有出现 fallback 失败。

### 六协议轮：TCP 吞吐、进程 CPU 与 RSS

每路由 3 次 8 秒 reverse run，取接收端 Mbps 中位数与该轮进程 CPU，再记录
整数 RSS MiB。进程 CPU 不包含 kernel/eBPF、softirq 和目标端成本，因此 eBPF
的 direct 行为 `0.00`，sing-box 的 TUN client 为 `0.37`。

| Protocol | honk Mbps / cores / MiB | dae Mbps / cores / MiB | sing-box Mbps / cores / MiB |
| --- | --- | --- | --- |
| direct | 9402 / 0.00 / 56 | 9408 / 0.00 / 53 | 9407 / 0.37 / 64 |
| hy2 | 3054 / 0.31 / 64 | 2975 / 0.59 / 60 | 1825 / 0.51 / 69 |
| tuic | 3586 / 0.34 / 64 | 3498 / 0.67 / 58 | 3386 / 0.77 / 67 |
| ss2022 | 9397 / 0.33 / 61 | 9400 / 0.38 / 57 | 9399 / 0.51 / 96 |
| trojan | 9383 / 0.35 / 59 | 9384 / 0.43 / 61 | 9371 / 0.69 / 94 |
| anytls-sb † | 9402 / 0.41 / 57 | 9387 / 0.50 / 61 | 9387 / 0.75 / 96 |
| anytls-go † | 9394 / 0.43 / 60 | 9370 / 0.54 / 63 | 9382 / 0.86 / 96 |

SS2022/Trojan/AnyTLS 的所有行都顶在 ~9.4 Gbps 的 LAN 上限，这些行比较的是
CPU 与 tail 而不是吞吐。HY2/TUIC 受 crypto 限制：honk 比 dae 高 2.7%/2.5%，
比 sing-box 高 67%/5.9%（sing-box HY2 只有 1825 Mbps）。honk 在
HY2/TUIC/SS2022/Trojan 上进程 CPU 最低（0.31/0.34/0.33/0.35，dae 为
0.59/0.67/0.38/0.43，sing-box 为 0.51/0.77/0.51/0.69）；按传输窗口计算后，两条 AnyTLS 路由
也是 honk 最省（0.41/0.43 对 dae 0.50/0.54、sing-box 0.75/0.86）。RSS：
honk 56–64 MiB，dae 53–63 MiB，sing-box 64–96 MiB。† AnyTLS 行在下方
CPU 分母修复后重测，其带宽、CPU 与 RSS 来自该轮（loaded 延迟表是独立阶段，
不受影响）。

### 六协议轮：UDP

15 次 ping 的 echo RTT 中位数，以及 iperf3 `-u -b 10G -l 1200 -R` 的接收端
Mbps、过载丢包和该轮进程 CPU。

| Protocol | honk RTT / Mbps (loss) / cores | dae RTT / Mbps (loss) / cores | sing-box RTT / Mbps (loss) / cores |
| --- | --- | --- | --- |
| hy2 | 0.593 ms / 1154 (83.5%) / 0.68 | 0.400 ms / 1176 (83.1%) / 0.76 | 0.088 ms / 0 (-) / 1.09 |
| tuic | 0.321 ms / 1236 (82.3%) / 0.68 | 0.538 ms / 1188 (82.9%) / 0.79 | 0.357 ms / 1065 (84.7%) / 1.41 |
| ss2022 | 0.323 ms / 2034 (65.8%) / 0.74 | 0.256 ms / 2799 (53.0%) / 1.24 | 0.113 ms / 2860 (52.0%) / 1.37 |
| trojan | 0.164 ms / 1713 (75.6%) / 0.71 | 0.119 ms / 2987 (55.5%) / 1.10 | 0.332 ms / 3539 (46.2%) / 1.57 |
| anytls-sb | 0.259 ms / 1546 (77.2%) / 0.55 | 0.348 ms / 1616 (76.1%) / 0.65 | 0.209 ms / 1385 (78.6%) / 1.16 |
| anytls-go | 0.190 ms / 1722 (74.8%) / 0.58 | 0.196 ms / 1772 (73.8%) / 0.71 | 0.283 ms / 1388 (78.9%) / 1.17 |

10 Gbps offer 是饱和过载探针，不是 WAN 丢包测量，因此每个 cell 都应出现
丢包。honk 在 HY2/TUIC 上核成本更低，TUIC 上比 dae 转发更多数据报（1236 对
1188 Mbps；HY2 为 1154 对 1176 Mbps 的近似平手）；dae 与 sing-box 保持
SS2022/Trojan 的 UDP 优势（相对 honk +38%/+74% 与 +41%/+107%）；sing-box
的 HY2 UDP arm 完全收不到数据，与 2026-10-11 结果一致。

#### AnyTLS CPU 分母修正

首轮 2026-10-24 测试用整条 `iperf3` 命令的墙钟时间作 CPU 分母。dae 的
AnyTLS client 在 8.00 秒传输结束后仍把命令挂住，整条命令耗时 18.02 秒
（honk 8.05–8.10 秒，sing-box 8.01–8.02 秒），所以 dae 原来的 0.21/0.24
核是把 CPU 除以了空转墙钟：这是测量假象，不是 dae 更省。以 50 ms 采样、按
iperf3 报告的传输窗口积分，dae 在 AnyTLS-SB 上是 **0.47–0.51** 核、
AnyTLS-Go 上是 **0.49–0.50** 核；honk（0.40–0.44）与 sing-box（0.75–0.93）
两种口径一致。同一假象也压低了 dae 的 AnyTLS-Go UDP cell（0.32 → 0.71 核）。

只有 AnyTLS 行受影响：其余协议的 client 都在传输结束后 0.02 秒内退出
（dae 5201–5204：8.008–8.018 秒）。`lab-bench.sh` 现在在命令比传输窗口长
超过 1 秒时改用 run JSON 里的传输时长，TCP 与 UDP 两条路径都如此；普通行
仍用命令墙钟，已发布的 cell 不变。上表 AnyTLS 行用该 driver 重测（每引擎
3 次带宽、15 次热请求、200 次 loaded open）；探针、两版 driver 与原始证据见
[`anytls-cpu/`](../bench/results/abc-2026-10-24-x86/anytls-cpu/)。

### 六协议轮：loaded 延迟稳定性

一条 reverse iperf3 压住同一路由，同时以绝对 250 ms deadline 打开 200 条
独立 HTTP 流。

| Protocol | honk load / p50 / p95 / p99 / max / failures | dae | sing-box |
| --- | --- | --- | --- |
| direct | 9406 / 3.274 / 4.014 / 4.246 / 4.425 ms / 0/200 | 9408 / 3.262 / 3.942 / 4.289 / 4.535 / 0/200 | 9412 / 3.324 / 3.985 / 4.124 / 4.544 / 0/200 |
| hy2 | 3069 / 1.807 / 2.164 / 2.510 / 2.764 / 0/200 | 2968 / 1.770 / 2.230 / 2.716 / 3.473 / 0/200 | 1958 / 10.874 / 27.428 / 31.544 / 103.865 / 0/200 |
| tuic | 3694 / 1.800 / 2.119 / 2.322 / 2.540 / 0/200 | 3427 / 1.805 / 2.082 / 2.584 / 3.045 / 0/200 | 3434 / 1.843 / 2.143 / 2.495 / 2.680 / 0/200 |
| ss2022 | 9400 / 3.032 / 8.048 / 10.650 / 15.152 / 0/200 | 9404 / 3.559 / 8.260 / 9.812 / 13.772 / 0/200 | 9406 / 3.142 / 7.923 / 11.375 / 15.407 / 0/200 |
| trojan | 9392 / 2.090 / 5.478 / 9.308 / 10.016 / 0/200 | 9388 / 5.937 / 16.839 / 23.754 / 25.519 / 2/200 | 9388 / 5.279 / 10.183 / 16.105 / 20.960 / 0/200 |
| anytls-sb | 9385 / 2.531 / 6.795 / 10.528 / 16.014 / 0/200 | 9385 / 2.506 / 8.376 / 13.721 / 15.919 / 0/200 | 9381 / 2.103 / 6.484 / 13.327 / 14.923 / 0/200 |
| anytls-go | 9377 / 2.583 / 11.239 / 17.631 / 20.323 / 0/200 | 9374 / 2.294 / 9.874 / 14.512 / 15.940 / 0/200 | 9375 / 2.202 / 9.785 / 14.548 / 20.702 / 0/200 |

单轮结果里 honk 在 HY2、TUIC、Trojan 与 AnyTLS-SB 上给出最低 p99；唯一的
失败是 dae 的 Trojan 路由（2/200）。sing-box 的 HY2 是离群点：约 2 Gbps 压力
下 p99 31.5 ms、max 104 ms。200 样本下 1–3 ms 的 p99 差异属于噪声：p99 就是
第二大的样本；AnyTLS 行重跑后 hot 与 p99 排名同时反转（见下）。

#### hot 与 tail 的方差

hot p50 列是刚重启引擎后的一次 15 请求突发（1 次预热），紧接上一行 50 秒
稳定性负载；p50 是第 8 个样本。间隔一段时间重跑同一批行，所有小差距都反转：

| 行（honk / dae） | 本轮 | 重跑 A | 重跑 B |
| --- | --- | --- | --- |
| hot anytls-go | 1.95 / 1.31 ms | 1.18 / 1.50 ms | 1.50 / 1.30 ms |
| hot anytls-sb | 1.83 / 1.73 ms | – | 1.36 / 1.35 ms |
| hot tuic | 1.87 / 1.76 ms | – | 1.62 / 1.81 ms |
| hot ss2022 | 2.16 / 1.97 ms | – | 1.39 / 1.49 ms |
| loaded p99 anytls-go | 17.63 / 14.51 ms | 13.06 / 15.58 ms | 15.62 / 20.50 ms |
| loaded p99 anytls-sb | 10.53 / 13.72 ms | – | 16.07 / 12.19 ms |
| loaded p99 ss2022 | 10.65 / 9.81 ms | – | 13.64 / 16.31 ms |

重跑 A 是 AnyTLS-Go 单行，重跑 B 是四行批次；两者使用同一 harness、配置与
binary。脱离 harness 的稳态探针（5 次预热、30 样本、空载主机）显示 honk 与
dae 在每条路由上相差不超过 0.05 ms，TUIC/SS2022 上更快（1.40 对 1.62 ms、
1.50 对 1.72 ms；AnyTLS-SB 1.13 对 1.08，AnyTLS-Go 1.03 对 1.02）。没有
引擎侧机制能解释本轮的 hot 差距：client 侧 connect 约 0.06 ms（eBPF 拦截），
AnyTLS stream 是乐观打开（SYN+PSH 入队，不等 SYNACK），20 个顺序请求共用
一条上游 AnyTLS session（honk 1 个 SYN，dae 2 个）。p99 离群样本在时间上
分散、不呈周期，honk 与 dae 的 >10 ms 样本数相当（AnyTLS-Go 12 对 10，
SS2022 3 对 2）。

这些单轮 hot/p99 差距只能当观察，不能当排名；可辩护的顺序需要交替重复
（如 Juicity 轮）或显著更多样本。探针脚本与两次重跑证据在
[`latency-analysis/`](../bench/results/abc-2026-10-24-x86/latency-analysis/)。

### REALITY 轮：VLESS Vision / REALITY / VMess

| Protocol | honk cold / hot p50 / p95 (ms) | bw / cores / MiB | dae cold / hot p50 / p95 | bw / cores / MiB | sing-box cold / hot p50 / p95 | bw / cores / MiB |
| --- | --- | --- | --- | --- | --- | --- |
| direct | 2.27 / - / - | 9404 / 0.00 / 50 | 2.03 / - / - | 9405 / 0.00 / 55 | 2.79 / - / - | 9410 / 0.38 / 94 |
| vless-vision | 46.8 / 53.2 / 55.1 | 9342 / 0.42 / 42 | 55.5 / 54.7 / 126.5 | 9389 / 0.48 / 58 | 58.3 / 57.6 / 111.5 | 9374 / 0.70 / 95 |
| vless-reality | 49.2 / 51.8 / 87.5 | 9381 / 0.39 / 43 | 56.0 / 59.0 / 113.9 | 9382 / 0.44 / 58 | 59.2 / 56.7 / 306.0 | 9391 / 0.68 / 97 |
| vmess | 3.27 / 1.89 / 2.71 | 9374 / 0.44 / 49 | 3.75 / 1.92 / 2.84 | 9352 / 0.44 / 54 | 3.62 / 2.65 / 3.23 | 9373 / 0.71 / 94 |

REALITY 行是端到端 TCP/REALITY，open 延迟包含服务端与 dest 的握手：三个
引擎都在 cold ~47–59 ms、hot ~52–59 ms，而 direct 约 2 ms。九个代理 cell 的
吞吐都到 LAN 上限，区分度来自 CPU、RSS 和 tail：honk 0.39–0.44 核，dae
0.44–0.48，sing-box 0.68–0.71；RSS 42–49 MiB 对 54–58 与 94–97。honk 在两条
VLESS 行上 cold 延迟与 p95 也最低。

| Protocol | honk UDP RTT / Mbps (loss) / cores | dae UDP | sing-box UDP |
| --- | --- | --- | --- |
| vless-vision | n/a | 0.394 ms / 2960 (55.6%) / 1.08 | 0.257 ms / 3551 (45.1%) / 1.60 |
| vless-reality | n/a | 0.412 ms / 2958 (56.1%) / 1.05 | 0.372 ms / 3964 (37.4%) / 1.59 |
| vmess | n/a | 0.228 ms / 3063 (54.3%) / 1.01 | 0.165 ms / 3535 (46.3%) / 1.55 |

honk 的 VLESS/VMess UDP 行为 `n/a`，因为 driver 的 `supports_udp` 仍未包含
它们：这是 harness 覆盖限制，不代表 honk 的 VLESS UDP 能力。dae 与
sing-box 各自承载了 2960–3964 Mbps 的 1200 字节数据报。

| Protocol | honk load / p50 / p95 / p99 / max / failures | dae | sing-box |
| --- | --- | --- | --- |
| direct | 9410 / 2.580 / 3.071 / 3.720 / 6.439 / 0/200 | 9411 / 2.487 / 3.010 / 3.134 / 3.226 / 0/200 | 9410 / 2.745 / 3.494 / 3.825 / 4.071 / 0/200 |
| vless-vision | 9346 / 52.265 / 62.936 / 70.616 / 72.671 / 0/200 | 9375 / 54.382 / 67.856 / 374.481 / 383.057 / 10/200 | 9359 / 58.284 / 92.605 / 112.158 / 241.201 / 0/200 |
| vless-reality | 9381 / 52.605 / 64.043 / 69.106 / 92.299 / 0/200 | 9371 / 57.697 / 75.125 / 236.901 / 243.325 / 0/200 | 9387 / 57.987 / 70.899 / 106.465 / 240.736 / 0/200 |
| vmess | 9384 / 2.472 / 9.898 / 16.946 / 20.468 / 0/200 | 9329 / 3.099 / 13.491 / 16.631 / 18.121 / 0/200 | 9371 / 3.067 / 9.033 / 12.632 / 15.850 / 0/200 |

在相同的饱和压力下，honk 把 REALITY tail 保持在 71 ms p99 以内且 0 失败；
dae 的 Vision arm 在 200 次 open 中失败 10 次、p99 到 374 ms（REALITY arm
p99 237 ms）；sing-box 的 p99 为 106–112 ms、max 241 ms。VMess 是所有引擎的低
RTT case；honk p50 比 dae 低 0.6 ms，p99 略高于 sing-box。

### Juicity 轮（honk vs dae）

| Protocol | honk cold / hot p50 / p95 (ms) | bw / cores / MiB | dae cold / hot p50 / p95 | bw / cores / MiB |
| --- | --- | --- | --- | --- |
| direct | 2.36 / - / - | 9407 / 0.00 / 48 | 2.56 / - / - | 9407 / 0.00 / 53 |
| juicity | 3.51 / 1.73 / 2.68 | 2787 / 0.30 / 50 | 8.29 / 1.71 / 2.04 | 2650 / 0.57 / 61 |
| juicity/udp | 0.364 ms / 1230 (82.6%) / 0.40 | - | 0.343 ms / 1187 (83.1%) / 0.68 | - |

honk 的 Juicity TCP 高 5.2%，进程 CPU 约为 dae 的一半；UDP 高 3.6%；cold
open 快 4.8 ms；RSS 50 对 61 MiB。loaded 稳定性相当：honk 2709 Mbps /
1.726 / 2.076 / 2.156 / 2.345 ms / 0 失败，dae 2612 / 1.719 / 2.000 /
2.350 / 2.667 ms / 0 失败。

### 结论

- 合并后的树保持 honk 在 2026-10-11 六协议轮的位置：SS2022/Trojan/AnyTLS
  达到 LAN 上限，HY2/TUIC 高 2.5–2.7%，crypto-bound 路由与两条 AnyTLS 路由在
  传输窗口修正后进程 CPU 最低。sing-box 的 HY2 仍是其弱项。
- 新的 REALITY 轮引擎差异最大：吞吐同为线速，但 honk 只需约 0.4 核与
  42–43 MiB，dae 为 0.44–0.48 核与 58 MiB，sing-box 为 0.68–0.71 核与
  95–97 MiB。该轮中两条 VLESS 路由上 honk 也是唯一 0 失败且 p99 低于 71 ms 的
  引擎。
- Juicity：honk 的 TCP 高 dae 5.2%、UDP 高 3.6%，核数约一半。
- 绝对数字是同机同 fixture 对比。共享 lab 的轮间方差约 ±5%；单流
  BBR/Hysteria2 行对主机负载最敏感。

## 结果（2026-10-20，x86 本地 fixture A/B/C）

本轮无法访问惯用的 `.70` 服务端：SSH 拒绝 lab key，六个协议端口和目标端口
也全部关闭。为了实际测量合并后的 `bench` 树而不是复用旧 binary，按既有 fallback
把服务端 fixture 放进 engine host 的 `labsrv` netns。**这是不同拓扑**：client、
engine 和 server 共享同一台 4 vCPU / 2 GiB 主机。direct 对照是主机内存路径
（eBPF 引擎 75–80 Gbps），不是 `.70` 的 9.4 Gbps LAN 上限；所有代理行都受
CPU/调度限制。因此绝对 Mbps、CPU 与 tail 不能与 2026-10-11 节直接比较；请用
同机跨引擎 delta 和旧 `.70` 节判断 WAN 行为。fixture 脚本、配置与原始证据在
[`abc-2026-10-20-x86-local`](../bench/results/abc-2026-10-20-x86-local/)，
本地启动方式见 [`bench/README.md`](../bench/README.md)。

| Engine | 实测 revision / build | 可执行文件 SHA-256 前缀 |
| --- | --- | --- |
| honk | `5d29dba6`（合并 `e936d022`），release/opt-s，静态 musl | `02453300bc55a4f3` |
| dae | [v2.1.1](https://github.com/daeuniverse/dae/releases/tag/v2.1.1)，`dbae2e82`，官方 generic x86-64 | `a217bf5edf5a5cac` |
| sing-box | [v1.14.3](https://github.com/SagerNet/sing-box/releases/tag/v1.14.3)，`7054cac5`，官方 amd64 | `768d31fa7f68debc` |

honk 编译 `ebpf,native-api,clash-api,mimalloc,rprx`，未配置 native listener，
因此不测活跃 native observation/UI 开销。服务端为 sing-box 1.14.3（HY2、
TUIC/cubic、SS2022、Trojan、AnyTLS）、官方 anytls-go 0.0.13、iperf3 3.21，
HTTP body 固定 1,024 字节，六端口路由契约与 2026-10-11 轮相同。SS2022 时间戳
验证未放宽；client 与 server 共享主机时钟。harness 只增加了 stale `daens`
清理保护，benchmark/collector 逻辑仍是
[metadata](../bench/results/abc-2026-10-20-x86-local/metadata.json) 中 hash
固定的版本。18 条代理路由均在对应 HTTP 请求运行时于服务端线上观察到
（HY2/TUIC 走 UDP/QUIC，其余四条走 TCP），见
[attribution.txt](../bench/results/abc-2026-10-20-x86-local/attribution.txt)。
sing-box 服务端日志保留了 client 取消和 cold TLS handshake 错误；那是被拒绝/
取消的 fixture 连接，不是 arm 失败。

### TCP 吞吐、进程 CPU 与 RSS

每条路由三轮 8s reverse iperf3，取接收端 Mbps 中位数与同轮进程 CPU，再记录
整数 RSS MiB。进程 CPU 不包含 kernel/eBPF、softirq 和目标端成本；direct 的
eBPF 行因此为 `0.00`，sing-box 的 TUN client 是用户态路径，为 `1.06`。

| Protocol | honk Mbps / process cores / MiB | dae Mbps / process cores / MiB | sing-box Mbps / process cores / MiB |
| --- | --- | --- | --- |
| direct | 74819 / 0.00 / 57 | 80356 / 0.00 / 49 | 29515 / 1.06 / 88 |
| hy2 | 8394 / 0.67 / 62 | 6778 / 1.01 / 71 | 5705 / 1.11 / 92 |
| tuic | 10122 / 0.82 / 59 | 6671 / 1.00 / 65 | 6705 / 1.25 / 92 |
| ss2022 | 27411 / 0.76 / 61 | 22068 / 0.76 / 60 | 23579 / 1.22 / 91 |
| trojan | 23551 / 0.78 / 61 | 16281 / 0.67 / 63 | 18036 / 1.40 / 96 |
| anytls-sb | 20050 / 0.87 / 68 | 19232 / 0.44 / 65 | 19236 / 1.36 / 96 |
| anytls-go | 19593 / 0.88 / 62 | 17567 / 0.42 / 61 | 17669 / 1.44 / 95 |

在这个 CPU 受限的 fixture 中，honk 赢得所有代理 TCP 行。相对 dae：
HY2 +23.8%、TUIC +51.7%、SS2022 +24.2%、Trojan +44.7%、AnyTLS-SB +4.3%、
AnyTLS-Go +11.5%。进程 CPU 在 HY2/TUIC/SS2022 更低，Trojan 高 16%；
两个 AnyTLS 在修正 dae 的 teardown 分母后也更低。按 Mbps per process core
归一化，honk 相对 dae 在 HY2/TUIC/SS2022/Trojan 为
+86.7%/+85.0%/+24.2%/+24.3%，在 **AnyTLS-SB/AnyTLS-Go 为
+24.0%/+27.3%**（使用 8 秒 transfer window）。相对 sing-box，honk 每行效率高
+62.9% 到 +143.8%。direct 比 dae 低 6.9%，那是 eBPF direct 路径，不是代理结果。

#### AnyTLS CPU 分母修正

dae 的 AnyTLS `iperf3` 命令在 8 秒传输结束后还会保持约 10 秒才退出；honk
在 8.0 秒返回。harness 用整条命令的 wall time 除 CPU tick，所以 dae
AnyTLS-SB/AnyTLS-Go 单元格（0.44/0.42 core）的分母约 18 秒。按 transfer
window 采样得到：

| Case | command wall | transfer | user cores | sys cores | total cores |
| --- | ---: | ---: | ---: | ---: | ---: |
| dae AnyTLS-SB | 18.017 s | 8.000 s | 0.446 | 0.561 | 1.008 |
| dae AnyTLS-Go | 18.010 s | 8.000 s | 0.437 | 0.526 | 0.964 |
| honk AnyTLS-SB | 8.044 s | 8.001 s | 0.367 | 0.480 | 0.847 |
| honk AnyTLS-Go | 8.045 s | 8.000 s | 0.369 | 0.475 | 0.844 |

9 秒 `perf stat` task-clock 窗口独立读到 dae 9.505 CPU-s（1.06 core）、honk
8.316 CPU-s（0.92 core）。两种方法都说明 honk 的 AnyTLS engine CPU 更低。
原始 TSV 保留 harness 值；修正只适用于 dae 两个 AnyTLS CPU 单元格，不影响
吞吐或 RSS。`.70` 轮的 dae AnyTLS 也受同一 teardown 影响，因此旧结论
“honk CPU 高于 dae”不成立。harness 应使用 iperf 报告的 transfer seconds 或
transfer-window CPU 采样，而不是整条命令 wall time；本轮没有修改正式
harness。临时 harness 副本用 transfer seconds 复测量化了修正：dae
AnyTLS-SB/Go **0.97/0.95 core**、honk **0.86/0.87**、sing-box
**1.35/1.42**；dae Trojan 保持 0.67。dae AnyTLS UDP 也从 0.23/0.26 修正为
0.53/0.60。临时 `opt-level=3` twin 在噪声内（download +0.9% 吞吐/+0.9% CPU；
upload −1.3%/−0.7%），不支持改 codegen。临时 patch 与数据在
[`anytls-profile/harness-window`](../bench/results/abc-2026-10-20-x86-local/anytls-profile/harness-window/)。

#### AnyTLS 热点

用与测量 binary 相同的 `just build-musl` 参数加 debug info 构建 twin
（`.text` 布局不同，只用于相对归因），在 8 秒 iperf3 运行期间用
`perf record -a -e cpu-clock -g` 采样。

| Profile | Mbps | AES-GCM | `memcpy` | AnyTLS demux | malloc | mpsc push |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AnyTLS-SB download | 20464 | 3.97% | 2.52% | 0.13% | 0.11% | 0.04% |
| Trojan download | 22149 | 4.44% | 1.12% | — | — | — |
| AnyTLS-SB upload | 17514 | 3.80% | 3.84% | — | — | — |
| Trojan upload | 18680 | 4.14% | <0.1% | — | — | — |

百分比是同一 system-wide profile 中所有 CPU-clock self samples 的份额；
只在表内横向比较。AES-GCM 两侧接近；AnyTLS 的差异是 `memcpy`：download
为 Trojan 的 2.25×，upload 中占主导。demux、mpsc push 和每帧分配都很小。
两侧 kernel 栈都以通用的 `tcp_recvmsg`/`_copy_to_iter` 与
`tcp_sendmsg`/`_copy_from_iter` 为主，因此 download 的 ~0.48 core system
time 不是 AnyTLS 特有成本。候选位置是 inbound
`read_frame_body` 分配加 `AnyTlsStream::poll_read` copy
（`crates/honk-outbound/src/proxy/anytls/mod.rs:1837`、`.../inbound.rs:672`），
以及 upload 的 `poll_write` copy 加 writer `encode_into` copy
（`.../mod.rs:1612`）。这是 profile 支持的候选，不是已实施的修复。

HY2/TUIC 的吞吐排序与 `.70` 相反（`.70` 为 honk 3135/3561 对 dae 3762/3306
Mbps）。本地去掉了 LAN 上限，CPU 成为瓶颈；这些行不能证明 WAN 改善。

### 首个请求与空载 hot 延迟

cold 指 daemon readiness 后首个请求，不保证物理 carrier 全冷。hot p50/p95
使用 15 次成功请求，耗时包含完整 HTTP body。

| Protocol | honk cold / hot p50 / hot p95 (ms) | dae cold / hot p50 / hot p95 (ms) | sing-box cold / hot p50 / hot p95 (ms) |
| --- | --- | --- | --- |
| direct | 0.604 / - / - | 0.431 / - / - | 0.658 / - / - |
| hy2 | 1.397 / 0.641 / 1.731 | 4.342 / 0.538 / 0.715 | 3.557 / 0.576 / 0.676 |
| tuic | 1.279 / 0.722 / 1.399 | 4.269 / 0.580 / 0.696 | 6.142 / 0.581 / 0.960 |
| ss2022 | 1.001 / 0.492 / 1.121 | 0.988 / 0.569 / 0.766 | 2.579 / 0.524 / 0.664 |
| trojan | 2.097 / 0.349 / 1.590 | 2.978 / 1.526 / 1.791 | 3.381 / 1.596 / 2.124 |
| anytls-sb | 0.945 / 0.536 / 0.850 | 2.527 / 0.485 / 0.581 | 2.357 / 0.523 / 0.646 |
| anytls-go | 3.136 / 0.547 / 0.737 | 2.119 / 0.539 / 0.616 | 2.955 / 0.557 / 0.696 |

honk 的 cold 中位数在四条路由低于 dae、五条低于 sing-box。但 hot p95 在
HY2、TUIC、SS2022、AnyTLS-SB、AnyTLS-Go 高于 dae，Trojan 是例外。也就是说，
本 fixture 的延迟弱点是 hot-open 路径，不是 daemon 启动；没有普遍延迟胜利：
AnyTLS-Go cold 比 dae 差，dae 的 HY2/TUIC hot p95 低于 1 ms。

### UDP 饱和负载

RTT 为 15 次 echo 中位数。带宽为单轮 8s reverse、10 Gbps 供给、1,200B
datagram。loss 是 iperf 接收端报告，不是常规负载可靠性结论；实际 sender
rate 可能低于供给，原始 JSON 保留该事实。

| Protocol | honk RTT ms / Mbps (loss) / process cores | dae RTT ms / Mbps (loss) / process cores | sing-box RTT ms / Mbps (loss) / process cores |
| --- | --- | --- | --- |
| hy2 | 0.060 / 950(90.3%) / 0.67 | 0.068 / 1038(89.6%) / 0.73 | 0.077 / 818(80.3%) / 1.08 |
| tuic | 0.070 / 885(90.8%) / 0.64 | 0.074 / 1119(88.5%) / 0.76 | 0.074 / 803(91.9%) / 1.22 |
| ss2022 | 0.038 / 1610(80.9%) / 0.67 | 0.053 / 1774(79.4%) / 0.88 | 0.046 / 1411(83.6%) / 0.72 |
| trojan | 0.036 / 1733(82.0%) / 0.71 | 0.040 / 2378(72.6%) / 0.96 | 0.050 / 2409(74.7%) / 1.22 |
| anytls-sb | 0.046 / 975(90.0%) / 0.45 | 0.058 / 948(89.9%) / 0.23 | 0.060 / 887(91.0%) / 0.78 |
| anytls-go | 0.044 / 1235(87.2%) / 0.55 | 0.101 / 1225(86.9%) / 0.26 | 0.064 / 1053(89.4%) / 0.91 |

honk 的 UDP RTT 在每条路由都低于 dae。饱和吞吐则落后 dae 的
HY2/TUIC/SS2022/Trojan（−8.5%/−20.9%/−9.2%/−27.1%），两个 AnyTLS 略领先；
所有 loss 都很高，因为供给超过这台共享主机的能力。`.70` 轮在
TUIC/SS2022/Trojan 上也是同一方向，所以不只是本地 fixture 效应；但两轮都
不能当作常规流量丢包率或统计优势。

### Loaded 延迟与保留的失败

每条路由 200 个绝对 250ms deadline，同路由一条 reverse stream，HTTP timeout
5s。分位数和最大值只计算成功请求；失败仍在 200 次尝试分母中。比较 tail 必须
同时看 achieved pressure。honk 七条路由均 0/200 失败；dae 9/4200
（AnyTLS-SB 8、SS2022 1）；sing-box 0/4200。

| Engine | Protocol | Load Mbps | p50 ms | p95 ms | p99 ms | Max ms | Failures |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 75098 | 0.651 | 1.144 | 1.908 | 3.427 | 0/200 |
| honk | hy2 | 6971 | 1.162 | 2.022 | 2.574 | 3.566 | 0/200 |
| honk | tuic | 9960 | 2.354 | 6.860 | 11.876 | 13.510 | 0/200 |
| honk | ss2022 | 27344 | 2.235 | 5.097 | 12.185 | 16.800 | 0/200 |
| honk | trojan | 21857 | 1.274 | 3.758 | 8.835 | 11.826 | 0/200 |
| honk | anytls-sb | 19343 | 1.648 | 12.578 | 16.618 | 17.100 | 0/200 |
| honk | anytls-go | 17782 | 1.575 | 8.546 | 15.335 | 17.373 | 0/200 |
| dae | direct | 79643 | 0.638 | 0.862 | 1.531 | 2.284 | 0/200 |
| dae | hy2 | 6309 | 1.371 | 2.137 | 2.624 | 3.114 | 0/200 |
| dae | tuic | 6728 | 1.389 | 1.949 | 2.364 | 2.947 | 0/200 |
| dae | ss2022 | 22580 | 1.834 | 11.303 | 24.670 | 25.002 | 1/200 |
| dae | trojan | 16233 | 3.498 | 15.834 | 25.935 | 32.078 | 0/200 |
| dae | anytls-sb | 19344 | 1.355 | 14.149 | 19.546 | 25.147 | 8/200 |
| dae | anytls-go | 17934 | 1.180 | 11.657 | 17.900 | 19.101 | 0/200 |
| sing-box | direct | 26707 | 2.153 | 4.057 | 4.967 | 6.716 | 0/200 |
| sing-box | hy2 | 5863 | 1.438 | 2.386 | 6.554 | 9.165 | 0/200 |
| sing-box | tuic | 6631 | 1.586 | 2.782 | 3.516 | 3.759 | 0/200 |
| sing-box | ss2022 | 22757 | 3.368 | 7.392 | 10.090 | 14.190 | 0/200 |
| sing-box | trojan | 17679 | 5.389 | 11.604 | 17.933 | 21.745 | 0/200 |
| sing-box | anytls-sb | 18791 | 1.841 | 4.783 | 10.199 | 15.555 | 0/200 |
| sing-box | anytls-go | 17314 | 1.832 | 5.332 | 8.357 | 18.252 | 0/200 |

honk TUIC 行的压力比 dae 高 48%（9,960 对 6,728 Mbps），所以 6.860 ms p95
是 capacity-edge 结果，不是等负载对照。honk 的 HY2/SS2022/Trojan tail 优于
dae；AnyTLS tail 远好于 dae 的 AnyTLS-SB 失败 arm，但在相近负载下差于
sing-box（p95 12.578/8.546 对 4.783/5.332 ms）。AnyTLS writer/stream 路径
因此是最明显的 tail 弱点；TUIC tail 需要限速复测后才能称为协议缺陷。

### 弱项与后续

| 发现 | 证据 | 候选成本与下一步实验 |
| --- | --- | --- |
| AnyTLS 每字节 copy | 差分 profile：`memcpy` 2.52% 对 Trojan 1.12%（download），3.84% 对 <0.1%（upload）；AES-GCM 接近；demux/mpsc/malloc <0.2%。Transfer-window CPU：honk 0.85 对 dae 1.01 core。 | 多出的用户态 copy 在 `read_frame_body` + `poll_read`（download）与 `poll_write` + writer `encode_into`（upload）。profile 支持的候选，未实施修复。下一步：owned-`Bytes`/vectored-write 实验，以 CPU 与 p95 为门槛。 |
| AnyTLS loaded tail | p95 12.578/8.546 ms，load 19,343/17,782 Mbps；sing-box 4.783/5.332 ms 为相近负载；dae 14.149/11.657 ms 且有 8 次失败。 | tail 可能共用 streaming/copy 路径。等负载复测；修复必须降低 p95 且不牺牲中位数/CPU。 |
| TUIC loaded tail | 9,960 Mbps 下 p95 6.860 ms；dae 6,728 Mbps 下 1.949 ms。 | collector 固定启动不限速 reverse stream。增加可选 `LOAD_BPS`，在 dae 压力下复测；只有 tail 仍存在才查 QUIC stream 调度。 |
| UDP 饱和 | 本 fixture 与 `.70` 轮均落后 dae 的 HY2/TUIC/SS2022/Trojan。 | 先用受控 1% loss / 65ms RTT lab 验证，再改 shared-source UDP；不要在 80–90% 饱和 loss 上直接调参，优先 profile 每包 lookup/permit 路径。 |
| size-oriented codegen | 测量 binary 使用 `Cargo.toml:151` 的 `opt-level = "s"`。 | 构建 `opt-level = 3` 候选，在 HY2/AnyTLS 上按既有门槛 A/B（≥3% 吞吐或 ≥10% CPU）。BoringSSL C++ 单独构建，只影响 Rust framing/relay/dispatch；先编译验证。 |

修正 teardown 分母后，AnyTLS 不再是 honk 相对 dae 的 CPU 效率劣势：honk
用更少 CPU、吞吐略高。剩余 AnyTLS 特有成本是相对 honk Trojan 路径的每字节
额外 `memcpy`；loaded tail 在相近压力下差于 sing-box。这些 copy 是 profile
支持的候选，不是已实施的修复。

### 原始证据与验证边界

[完整 campaign evidence](../bench/results/abc-2026-10-20-x86-local/) 保留
stdout/stderr、两个 TSV、63 个 TCP 与 18 个 UDP JSON、全部 4,200 次 loaded
尝试、每路由 summary 与 engine log、冻结的 client/server 配置与 fixture
脚本、binary hash、主机遥测、路由归因和清理 receipt。
[AnyTLS profile](../bench/results/abc-2026-10-20-x86-local/anytls-profile/)
另外保存 transfer-window CPU 修正、差分 `perf` 报告和诊断 driver；原始
76–81 MB `perf.data` 留在 `.49`，未提交。运行结束后 fixture 已移除；`.49`
无 benchmark 引擎、`labsrv`、`dae0` 或 `daens`，lab netns 已重建。
构建（`just build-musl 'ebpf,native-api,clash-api,mimalloc,rprx'`）、
`bash -n bench/lab-bench.sh`、五个 collector test 和 18 条路由归因均通过。
本轮没有运行完整 workspace、`test-routing`、`test-netns`、ARM benchmark 或
活跃 native API/UI；没有改动生产网关。

## 结果（2026-10-11，honk / 上游 dae / sing-box A/B/C）

在 `.49` 顺序执行一轮完整 x86 对照，时间为 **2026-10-10 19:54:28–20:34:38 UTC**
（UTC+8 的 2026-10-11 03:54–04:34）。覆盖六协议和三个 direct 对照：63 轮 TCP
带宽、18 轮 UDP 带宽、4,200 次负载下的定时 HTTP 请求；不是多轮统计对照。

| Engine | Measured revision / build | Executable SHA-256 prefix |
| --- | --- | --- |
| honk | `f65f0548` (merge of `fba795da`), release/opt-s, static musl | `f4c4a83bf21b7ac7` |
| dae | [v2.1.1](https://github.com/daeuniverse/dae/releases/tag/v2.1.1), `dbae2e82`, official generic x86-64 | `a217bf5edf5a5cac` |
| sing-box | [v1.14.3](https://github.com/SagerNet/sing-box/releases/tag/v1.14.3), `7054cac5`, official amd64 | `768d31fa7f68debc` |

dae 与 sing-box 在解析版本时均为上游最新**稳定版**，不是 rolling/nightly 或 dae
fork。完整 SHA、release asset 校验和、八个输入文件 hash 与精确命令见
[metadata](../bench/results/abc-2026-10-11-x86/metadata.json) 和
[command receipts](../bench/results/abc-2026-10-11-x86/commands.jsonl)。

honk 编译了 `ebpf,native-api,clash-api,mimalloc,rprx`，但未配置 native listener，
因此不测活跃 native observation/UI 开销。沿用 lab 的 QUIC MTU 1452 与 UDP warm
count 8；三端 TUIC 均为 cubic。配置使用不与节点重名的 `proxy-*` group，以及本地
HTTP/DNS 健康目标和 3600s 间隔。物理服务端是 NTP 已同步的 i9-13900H workstation，
20 个逻辑 CPU、31 GiB RAM；使用 sing-box 1.14.3、官方 anytls-go 0.0.13、iperf3
3.21，HTTP body 固定 1,024 字节。比较的是这些精确配置栈，不是各引擎完全未改的
默认配置，也不是旧服务端版本的回归对照。

**预检不能省。** 旧 sing-box echo 规则会回落 direct，现已显式路由六个 UDP echo
端口。服务端观察到的源地址在 18 条 TCP 和 18 条 UDP 代理路由中均为 `.70`，
direct 对照为 `.49`；真实 TCX/TUN 附着见
[attribution-ready.json](../bench/results/abc-2026-10-11-x86/attribution-ready.json)。
SS2022 起初因客户端慢 34.878s 而拒绝三个引擎；VM RTC tick 校时失败后，以已同步
的物理服务端做一次性校准，实测偏差降到 -0.056s。没有放宽时间戳验证，也没有改动
VM 的 NTP 策略。失败预检仍保留，未混入以下正式表格。

### TCP 吞吐、进程 CPU 与 RSS

每条路由三轮 8s reverse iperf3，取接收端 Mbps 中位数与同轮进程 CPU，再记录
整数 RSS MiB。进程 CPU 不包含 kernel/eBPF、softirq 和服务端成本；RSS 不包含
内核 map 分配。

| Protocol | honk Mbps / process cores / MiB | dae Mbps / process cores / MiB | sing-box Mbps / process cores / MiB |
| --- | --- | --- | --- |
| direct | 9406 / 0.00 / 45 | 9405 / 0.00 / 47 | 9400 / 0.40 / 63 |
| hy2 | 3135 / 0.31 / 42 | 3762 / 0.70 / 63 | 2860 / 0.62 / 66 |
| tuic | 3561 / 0.35 / 44 | 3306 / 0.65 / 59 | 3265 / 0.75 / 72 |
| ss2022 | 9396 / 0.30 / 47 | 9399 / 0.36 / 62 | 9389 / 0.48 / 71 |
| trojan | 9380 / 0.35 / 47 | 9390 / 0.43 / 60 | 9383 / 0.65 / 71 |
| anytls-sb | 9394 / 0.40 / 47 | 9381 / 0.22 / 63 | 9388 / 0.71 / 73 |
| anytls-go | 9387 / 0.44 / 46 | 9380 / 0.24 / 63 | 9376 / 0.87 / 76 |

SS2022、Trojan 与两个 AnyTLS TCP 路由达到 native direct 路径上限。本轮 honk HY2
比 dae 低 16.7%、比 sing-box 高 9.6%，TUIC 分别高 7.7%/9.1%。honk 的代理行 RSS
均更低；进程 CPU 各行均低于 sing-box，QUIC/SS2022/Trojan 也低于 dae，但**两个
AnyTLS server 的进程 CPU 都高于 dae**。

**勘误（2026-10-20）：** dae 的 AnyTLS iperf 命令在 8 秒传输结束后还会保持
约 10 秒，所以上表 dae AnyTLS CPU 单元格使用约 18 秒分母。按 transfer window
采样，dae AnyTLS 约为 0.5 core，不是 0.22/0.24；“高于 dae”的结论不成立。
见 2026-10-20 的 AnyTLS 修正与 profile。

### 首个请求与空载 hot 延迟

cold 指 daemon readiness 之后的首个请求，不保证物理 carrier 全冷；启动探测和
连接池可能已预热。hot p50/p95 使用 15 次请求尝试，耗时包含完整 HTTP body。
direct 对照的原始首请求只有一次，不是代理行的三次重启中位数；没有 direct UDP
带宽行。

| Protocol | honk cold / hot p50 / hot p95 (ms) | dae cold / hot p50 / hot p95 (ms) | sing-box cold / hot p50 / hot p95 (ms) |
| --- | --- | --- | --- |
| hy2 | 4.114 / 1.512 / 3.186 | 6.111 / 0.863 / 0.983 | 9.475 / 0.954 / 1.372 |
| tuic | 4.001 / 1.867 / 3.444 | 7.983 / 1.115 / 1.507 | 14.772 / 1.336 / 2.075 |
| ss2022 | 3.343 / 2.171 / 3.136 | 3.933 / 2.225 / 2.869 | 3.659 / 1.591 / 3.761 |
| trojan | 6.695 / 0.657 / 7.191 | 9.316 / 5.301 / 8.632 | 9.684 / 4.174 / 5.904 |
| anytls-sb | 3.662 / 2.187 / 2.789 | 8.087 / 1.730 / 4.468 | 7.268 / 1.328 / 1.695 |
| anytls-go | 3.510 / 1.820 / 2.242 | 7.700 / 1.282 / 2.598 | 9.646 / 1.307 / 1.932 |

### UDP 饱和负载

RTT 为 15 次 echo 尝试中收到响应的中位数，没有保留逐个 echo sample。带宽为
单轮 8s reverse、配置供给 10 Gbps、datagram 1,200B。loss 是 iperf 接收端报告的
packet loss，不是常规负载下的可靠性结论；实际 sender rate 可能低于配置供给，
原始 JSON 保留了该事实。

| Protocol | honk RTT ms / Mbps (loss) / process cores | dae RTT ms / Mbps (loss) / process cores | sing-box RTT ms / Mbps (loss) / process cores |
| --- | --- | --- | --- |
| hy2 | 0.424 / 1101(86.5%) / 0.49 | 0.440 / 1056(87.1%) / 0.70 | 0.491 / invalid / — |
| tuic | 0.334 / 989(69.9%) / 0.55 | 0.771 / 1147(86.0%) / 0.76 | 0.305 / 1027(87.4%) / 1.41 |
| ss2022 | 0.280 / 2078(69.1%) / 0.76 | 0.197 / 2908(56.9%) / 1.27 | 0.178 / 2963(55.9%) / 1.41 |
| trojan | 0.128 / 1773(78.4%) / 0.73 | 0.193 / 3142(59.6%) / 1.12 | 0.201 / 3426(55.4%) / 1.51 |
| anytls-sb | 0.200 / 1600(79.4%) / 0.56 | 0.228 / 1550(80.3%) / 0.63 | 0.164 / 1398(81.1%) / 1.17 |
| anytls-go | 0.269 / 1726(78.4%) / 0.59 | 0.204 / 1656(79.1%) / 0.30 | 0.187 / 1327(82.6%) / 1.18 |

sing-box HY2 UDP 虽已收到数据，但最终为 `server test duration expired`，没有
terminal receiver totals。driver 的 `0(-)` 应读作 **invalid**，不是零吞吐，
不能以 partial interval 替代完整总量；失败传输的 CPU 也不参与比较。原始证据为
[raw/sing-box-5201.udp.json](../bench/results/abc-2026-10-11-x86/raw/sing-box-5201.udp.json)。
UDP 并非 honk 全胜：TUIC、SS2022、Trojan 落后于其他端；两个 AnyTLS rate 有
竞争力，但单次饱和 sample 不能证明常规流量丢包率或统计优势。

### Loaded 延迟与保留的失败

每条路由 200 个绝对 250ms deadline，同一路由一条 reverse stream，HTTP timeout
5s。分位数和最大值都只计算**成功请求**；失败仍在 200 次尝试的分母中。比较尾延迟
必须同时看 achieved load，不是固定压力实验。最大调度偏差为 2.036ms。

| Engine | Protocol | Load Mbps | p50 ms | p95 ms | p99 ms | Max ms | Failures |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 9408 | 3.284 | 4.040 | 5.335 | 1007.208 | 0/200 |
| honk | hy2 | 3048 | 1.797 | 2.239 | 2.623 | 2.868 | 3/200 |
| honk | tuic | 3645 | 1.843 | 2.130 | 2.560 | 2.894 | 0/200 |
| honk | ss2022 | 9402 | 2.868 | 7.369 | 13.012 | 15.906 | 0/200 |
| honk | trojan | 9389 | 2.062 | 5.497 | 8.842 | 10.256 | 0/200 |
| honk | anytls-sb | 9388 | 2.567 | 8.609 | 15.587 | 20.091 | 0/200 |
| honk | anytls-go | 9354 | 2.496 | 12.660 | 17.358 | 23.054 | 0/200 |
| dae | direct | 9404 | 2.761 | 3.780 | 4.260 | 4.501 | 0/200 |
| dae | hy2 | 3509 | 1.466 | 2.086 | 3.413 | 13.956 | 0/200 |
| dae | tuic | 3436 | 1.807 | 2.035 | 2.378 | 3.012 | 2/200 |
| dae | ss2022 | 9402 | 3.589 | 8.266 | 10.356 | 11.732 | 0/200 |
| dae | trojan | 9380 | 5.491 | 11.818 | 22.010 | 45.234 | 0/200 |
| dae | anytls-sb | 9378 | 2.546 | 10.662 | 14.092 | 14.591 | 1/200 |
| dae | anytls-go | 9386 | 2.199 | 5.161 | 8.523 | 15.687 | 0/200 |
| sing-box | direct | 9407 | 2.416 | 3.014 | 3.543 | 1034.084 | 0/200 |
| sing-box | hy2 | 2672 | 8.913 | 20.916 | 25.597 | 30.111 | 0/200 |
| sing-box | tuic | 3288 | 1.856 | 2.294 | 2.699 | 3.050 | 0/200 |
| sing-box | ss2022 | 9396 | 3.547 | 7.961 | 11.641 | 42.763 | 0/200 |
| sing-box | trojan | 9364 | 5.433 | 11.841 | 17.291 | 19.717 | 0/200 |
| sing-box | anytls-sb | 9363 | 2.393 | 7.450 | 12.844 | 19.851 | 0/200 |
| sing-box | anytls-go | 9370 | 2.380 | 7.423 | 15.281 | 17.170 | 0/200 |

honk HY2 有三次约 5s timeout，不能被成功请求的 2.623ms p99 掩盖；dae TUIC 有
两次 timeout、dae AnyTLS-SB 一次，其余均 0/200。honk 和 sing-box 的 direct
对照各有约 1s 的成功请求离群值。因此，小 p99 单元格不能推出无条件 tail 或全面
延迟稳定性胜利。

### 失败 UDP 的独立复测

在 **20:36:59–20:40:52 UTC**，按同一完整方法复测 sing-box direct/HY2。没有改动
版本、配置、供给、datagram 长度或采样，本次 UDP 得到完整总量。额外六个 TCP
sample、一个 UDP sample 和 400 次 loaded 尝试独立存放于
[followup-summary.json](../bench/results/abc-2026-10-11-x86/followup-summary.json) 与
[hy2-udp-followup-raw](../bench/results/abc-2026-10-11-x86/hy2-udp-followup-raw/)，
不回填主轮 invalid UDP 单元格，也不替换主轮 TCP/tail 数据。

| Scope | TCP Mbps | UDP Mbps (loss) | Loaded Mbps | Loaded p99 ms | Loaded max ms | Failures |
| --- | --- | --- | --- | --- | --- | --- |
| sing-box HY2 follow-up | 2338 | 895(19.9%) | 2720 | 184.167 | 364.786 | 0/200 |

复测 HY2 TCP 比主轮低 18.3%，loaded tail 也有明显变化。历史约 ±5% 的 lab
波动不是本轮的统计界限；一轮主矩阵加一次针对性复测，不能确立稳定丢包率或
统计排名。

### 原始证据与验证边界

[完整 campaign evidence](../bench/results/abc-2026-10-11-x86/) 保留原始 stdout/
stderr、pipe-delimited TSV、63 个 TCP 与 18 个 UDP JSON、全部 4,200 次 loaded
尝试、每路由 summary/pressure JSON、engine log、冻结的 driver/config、binary
hash、clock/cleanup receipt 和失败预检；不以复测的有利结果静默替换主轮数据。
没有保留逐次 cold/hot 耗时或 daemon CPU tick/wall-time sample；stdout/TSV
保留了汇总值，但不能仅凭 bandwidth JSON 独立重建这些指标。
最终 [cleanup.json](../bench/results/abc-2026-10-11-x86/cleanup.json) 验证 `.49`
无 benchmark 引擎或 `dae0`/`daens`，两个持久序列 pin 均保留且未重置；重建后的
lab namespace/NAT 与原 SSH/Tailscale/einat 均保留。`.70` 的十个临时服务已停止，
原 mock honk 进程及既有 benchmark 档案没有被清除。
静态构建、完整 outbound gate（rprx off/on）、七个 Criterion smoke case、五个
collector test 与真实 36 路由归因均通过，见
[verification.json](../bench/results/abc-2026-10-11-x86/verification.json)。
本轮没有运行完整 workspace、`test-routing`、`test-netns`、活跃 native API/UI
或 ARM benchmark；没有改动生产网关。

## 结果(2026-09-02,dae 家族矩阵:dae / kdae / cdae 对 sing-box)

在 x86 实验机(`10.10.10.49`)上用 `bench/lab-bench.sh` 做同机对照,协议面为完整
六协议(hy2、tuic、ss2022、trojan、anytls-sb、anytls-go)加 direct 基线。
**本轮无 honk arm** —— 矩阵只比较三个 dae 家族构建与 sing-box 1.13.18
(TUN client 运行在 lab netns 内)。

| 引擎 | 版本 |
| --- | --- |
| dae | 上游 `unstable-20260729.r987.2a007b39` |
| kdae | `unstable-20260824.r1142.ec957346`(go1.26.0 newinliner/simd) |
| cdae | LostAttractor/dae `dev`,`unstable-20260828.r1.2630677`(源码构建,go1.25.7) |
| sing-box | 1.13.18 |

**cdae 的协议面在编译期受限。** `dev` 分支在 `component/outbound/outbound.go`
中注释掉了 tuic/juicity/vless/vmess/ssr,且其 anytls dialer 运行时注册失败
("no conn creator registered for anytls"),因此 cdae 实际可用面只有
**hy2 + ss2022 + trojan**;其 tuic/anytls 行记为 0/invalid,不是性能数字。
cdae 的解析器还拒绝 `dial_mode`、`tcp_check_url`、`udp_check_dns`、
`check_interval`、`check_tolerance`,harness 的 3600s 健康检查抑制对 cdae
arm 不生效(`cdae-lab.dae` 即 `dae-lab.dae` 去掉这些键)。

带宽(iperf3 `-R`,3 次取中位数,Mbps):

| 协议 | dae | kdae | cdae | sing-box |
| --- | ---: | ---: | ---: | ---: |
| direct | 9404 | 9407 | 9405 | 9404 |
| hy2 | 3066 | 3105 | 3222 | 3206 |
| tuic | 3339 | 3371 | n/a | 2910 |
| ss2022 | 9394 | 9399 | 9405 | 9395 |
| trojan | 9388 | 9388 | 9397 | 9384 |
| anytls-sb | 5614 | 5600 | n/a | 5659 |
| anytls-go | 9378 | 9380 | n/a | 9378 |

UDP(发送 10 Gbps,接收占发送比):hy2 ≈ 0.97–1.12 Gbps(84–86%),ss2022 ≈
2.7–2.9 Gbps(~51%),trojan ≈ 2.9–3.7 Gbps(42–56%),anytls ≈ 1.3–1.8 Gbps
(73–79%)—— 共有行上各引擎在噪声范围内一致。

延迟:除上游 dae 的 tuic 路径外,所有引擎冷启动约 2–9 ms、热态 p50/p95 约
1.7–3.7 ms;dae tuic 存在固定的每流惩罚 —— **冷 82.8 ms,热 p50 78.8 ms**,
而 kdae 为 23.0 / 17.9 ms,sing-box 为 7.6 / 2.2 ms。kdae 已修掉大部分惩罚,
仍残留约 18 ms。

带载延迟稳定性(同一条 outbound 上一条反向 iperf3 流压载,200 个流以
250 ms 节拍注入;p99 ms):

| 协议 | dae | kdae | cdae | sing-box |
| --- | ---: | ---: | ---: | ---: |
| direct | 4.86 | 4.72 | 5.02 | 4.88 |
| hy2 | 3.25 | 3.10 | 3.28 | 3.40 |
| tuic | **77.50** | 17.28 | n/a | 2.93 |
| ss2022 | arm-failed\* | 16.03 | 15.87 | 15.32 |
| trojan | 25.58 | 22.42 | 19.62 | 22.42 |
| anytls-sb | 2.70 | 2.86 | n/a | 2.69 |
| anytls-go | 16.43 | 19.87 | n/a | 16.12 |

\* 上游 dae 的 ss2022 带载延迟 arm 三次重试均未采到数据,该行留空而非插值。
其余单元格失败数均为 0/200,仅 kdae anytls-go 为 4/200。

各引擎完整 harness stdout、raw TSV 行与原始配置文件见
[`engine-matrix-2026-09-02`](../bench/results/engine-matrix-2026-09-02/)。

## 结果(2026-08-27,代理 QUIC adapter 回归门槛)

已合并 PR #75 的路径加 follow-up 修复 `0ecc101`,与 PR 前 main `4c3ade3`
对比。fixture 使用生产 ownership 形态：一个共享 `NodeRuntime`,每轮经真实
Hysteria2、TUIC 或 Juicity 实验室服务端建立新的 packet flow,再向本机 H3
服务端完成一次内层 QUIC 握手。每个协议运行 30 组交替 A/B,每个进程 100 个
计量握手加 5 个 warmup（每个 arm 3,000 个计量样本）。它隔离 adapter/probe
成本,不是用户数据容量 benchmark。

| 外层传输 | baseline / candidate total 中位数 ms | 配对中位 delta | 95% bootstrap 区间 | 配对 p95 delta | 进程 CPU delta |
| --- | ---: | ---: | ---: | ---: | ---: |
| Hysteria2 | 0.916 / 0.923 | +0.688% | -1.328% 至 +2.115% | -3.054% | -7.709% |
| TUIC | 0.920 / 0.937 | +1.580% | -1.136% 至 +4.108% | +2.511% | -7.136% |
| Juicity | 0.857 / 0.873 | +2.549% | -0.152% 至 +3.893% | +2.848% | -7.336% |

所有区间均包含零,因此本轮没有证实延迟回归。点估计都低于 3%,但 TUIC 与
Juicity 的上界超过 3%；样本不能证明最坏回退低于 3%。candidate 的 9,000 个
计量握手全部完成且 stderr 为空。进程 CPU 行把子进程 CPU 除以全部 105 个
probe,并包含摊销后的进程启动；这是辅助证据,不代表代理吞吐。

另做每个进程 5,000 次 probe 的紧循环,检查 endpoint worker 退休。其密度远高于
生产环境的周期 probe：

| 外层传输 | baseline / candidate peak RSS KiB | baseline / candidate wall s |
| --- | ---: | ---: |
| Hysteria2（两轮） | 231104–247072 / 44048–45520 | 3.69–3.98 / 4.27–4.42 |
| TUIC | 246944 / 43520 | 3.64 / 4.36 |
| Juicity | 217840 / 43088 | 4.27 / 4.26 |

follow-up 在该 churn 下把 peak RSS 从 213–241 MiB 压到约 43–46 MiB。
Hysteria2 与 TUIC 为确定性 worker 清理在 5,000 次连续 probe 中最多多付
0.72 秒；Juicity 持平。这是清理压力成本,不是热数据路径回归。

同一轮在最终 A/B 前暴露并修复两个正确性问题：即使 advertise 1252 字节,
quic-go 仍可能合并出 1280 字节 first flight；成功 probe 关闭 endpoint 前必须
先 drop connection handle。完整二进制/源码 hash、配对 raw row、置信区间、
soak row、配置与原样 runner 位于
[`quic-proxy-impact-2026-08-27`](../bench/results/quic-proxy-impact-2026-08-27/)。

## 结果(2026-08-26,QUIC profile 与优化门槛)

本轮对 source `0bd6135` 的现有有界 GSO 实现及独立 Juicity 候选
`429c540` 进行 profile。x86 主机固定使用同一个 musl 二进制
(`e8750633...`)、同一份 1452 字节配置、8 秒 iperf3 窗口及 5 轮交替 arm。
`reverse` 是 server-to-client 下载,`forward` 是 client-to-server 上传。
硬件 PMU event 不可用,故 profile 证据由 userspace `cpu-clock` sample、进程
task-clock、syscall 计数及端到端吞吐/CPU 结果组成。

完整 harness 复现沿用现有 3-cold / 15-hot / bandwidth 3 轮中位数 /
200-loaded-stream contract：

| 路径 | Cold / hot p50 / p95 ms | Bandwidth Mbps / CPU / RSS MiB | Loaded Mbps / p99 / max ms / 失败 |
| --- | ---: | ---: | ---: |
| direct | 16.225 / - / - | 9403 / 0.00 / 45 | 8918 / 8.177 / 13.614 / 0 |
| HY2 | 8.561 / 1.076 / 3.060 | 6037 / 0.55 / 52 | 5852 / 6.462 / 10.375 / 6 |
| TUIC | 2.759 / 1.101 / 1.988 | 3355 / 0.34 / 43 | 3428 / 4.189 / 11.539 / 0 |

### 实测瓶颈

| 协议/方向 | 基线中位数 Mbps / CPU 核 | 最大 userspace self sample |
| --- | ---: | --- |
| HY2 reverse | 6369 / 0.636 | AES-GCM decrypt 14.0%；`memcpy` 12.9% |
| HY2 forward | 5035 / 1.037 | `memcpy` 15.6%；AES-GCM encrypt 10.7%；mutex contention 6.9% |
| TUIC reverse | 3758 / 0.367 | `memcpy` 13.7%；AES-GCM decrypt 11.7% |
| TUIC forward | 5279 / 0.855 | `memcpy` 12.3%；mutex contention 9.3%；AES-GCM encrypt 8.5% |

其余领先 sample 为 Quinn packet assembly/decoding、connection driver 及
receive reassembly。主要成本因此位于共享 QUIC crypto 与 buffer movement,
而非某一个协议的 framing。诊断用 `strace` arm 在一个 forward 窗口内观测到
约 9.5–10.2 万次 `sendmsg` 与 7.8–9.3 万次 `recvmmsg`,但 tracing 将吞吐降至
约 1.1–1.2 Gbps；这些计数不作为生产性能对比。

Instrumented endpoint 实报 MTU 1452、kernel GSO capacity 64、application cap
16 及 GRO 64。在 43 个 connection snapshot 中,connection 与 stream
flow-control blocked counter 均未增长。这既确认实际 GSO cap,也没有为扩大
receive window 提供实测依据。

### GSO 与 MTU

权威 x86 对比在每轮中交替执行 disabled、cap-4 与 cap-16。delta 是同轮
配对百分比变化的中位数,不是聚合中位数的比值。

| 模式 | HY2 Mbps / CPU | HY2 配对 delta | TUIC Mbps / CPU | TUIC 配对 delta |
| --- | ---: | ---: | ---: | ---: |
| GSO off | 6365 / 0.628 | control | 3319 / 0.343 | control |
| GSO cap 4 | 6231 / 0.618 | +1.88% | 3280 / 0.328 | -7.65% |
| GSO cap 16 | 6576 / 0.635 | +3.63% | 3367 / 0.340 | -0.15% |

Cap 16 重现现有 HY2 增益,但未改善 CPU,TUIC 也没有同等增益。单次 cap-8
arm 噪声较大,cap-32 HY2 arm 未产生有效吞吐。没有证据支持放宽现有 cap,
也没有证据支持改变抗黑洞的 1252 字节 scalar 默认值。

最终 ARM arm 使用同一二进制/配置 contract,并以 monotonic nanosecond
clock 计算进程 CPU：

| 模式 | HY2 Mbps / CPU | HY2 配对 delta | TUIC Mbps / CPU | TUIC 配对 delta |
| --- | ---: | ---: | ---: | ---: |
| GSO off | 334 / 1.419 | control | 249 / 1.059 | control |
| GSO cap 4 | 330 / 1.440 | -1.29% | 227 / 1.001 | -8.99% |
| GSO cap 16 | 335 / 1.423 | -0.10% | 233 / 1.020 | -7.73% |

ARM 未呈现 GSO 增益。TUIC sample 波动较大,但两个启用模式的中位数都更低；
其 CPU 降低伴随 delivered throughput 降低,不构成效率改善。

### Owned QUIC stream relay 原型

该原型仅对 concrete Quinn stream 以 `RecvStream::read_chunk` 与
`SendStream::write_chunk` 替换 generic `AsyncRead` buffering,并保留现有
half-close、字节计数、取消及 idle-drain 语义。

| TUIC 模式/方向 | 中位数 Mbps / CPU | 配对吞吐 delta |
| --- | ---: | ---: |
| 现有 relay,reverse | 3368 / 0.344 | control |
| owned-chunk relay,reverse | 3327 / 0.334 | -1.22% |
| 现有 relay,forward | 5611 / 0.952 | control |
| owned-chunk relay,forward | 5852 / 0.957 | +0.01% |

reverse 回退、配对 forward 吞吐不变且 CPU 仅降低 2.6–2.9%,未通过无回退及
10% CPU 门槛。原型已回滚；concrete QUIC stream 继续使用现有 relay。

### TUIC congestion 受控 sweep

| 算法 | Reverse Mbps / CPU / retransmits | Forward Mbps / CPU / retransmits |
| --- | ---: | ---: |
| cubic | 3474 / 0.346 / 1 | 5709 / 0.924 / 9 |
| BBR | 3454 / 0.337 / 0 | 5488 / 1.042 / 154 |
| New Reno | 3511 / 0.353 / 0 | 5407 / 0.867 / 15 |

Cubic 保持最高 forward 中位数。BBR 在该方向消耗更多 CPU 且 retransmit
更多；New Reno 的 forward 吞吐更低。因此 TUIC 保留现有 cubic 默认值。
在没有 changed bottleneck metric 时,未推广 window、ACK、PMTUD、fairness
或 buffer tuning。

### Allocation 清理

Juicity 候选 `429c540` 以 `write_chunk(Bytes)` 将编码 frame 交给 Quinn,
并把 UDP payload 直接解码到调用方 buffer。3 轮配对的 500-packet allocation
实验约测得 4,828 对 5,839 次 allocation call,即 call 减少 17.3%、allocated
bytes 约减少 15%。聚焦 receive 测试也在 4096 个 frame 间保持同一个调用方
buffer。该 allocation-specific cleanup 作为 `d4fd31a` 由
[PR #73](https://github.com/daeuniverse/honk/pull/73) 合并。
4 个聚焦测试与全部 546 个 `honk-outbound` 测试均通过,format 与 Clippy
也保持 clean。

候选相对 baseline 的本地 Juicity 端到端 arm 噪声过大,不足以把吞吐变化归因于
该清理。外围 UDP endpoint receive path 已复用一个固定 buffer 并直接从中发送；
更广泛的 ownership 改动只会增加 API 与 lifetime 复杂度,却不能删除已测
allocation,故未修改。该 fixture 也不含 Salamander,因此未作推测性优化。

### 当前 honk 与 dae 的 Juicity 对比

现有官方 Go `juicity-server` v0.4.3 endpoint 位于
`10.10.10.70:2451`。专用配对配置复用目标槽 1,QUIC MTU 固定为 1452 字节。
当前 main `4c3ade3` 由标准 `just build-musl` recipe 构建
(`ba2821e3...`),与 x86 主机上的 dae
`unstable-20260824.r1142.ec957346` (`f2dc44b5...`)对比。3 轮完整 harness
保留 3-cold / 15-hot / bandwidth 3 次中位数 / 200-loaded contract；另做 5 轮
capacity 配对,每个 arm 使用一个 8 秒 bandwidth 窗口。百分比 delta 均为同轮
配对 delta 的中位数。

| Contract | honk TCP Mbps / CPU / RSS | dae TCP Mbps / CPU / RSS | 配对 TCP 吞吐 / CPU | honk UDP Mbps / CPU / loss | dae UDP Mbps / CPU / loss | 配对 UDP 吞吐 / CPU |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 完整,3 轮 | 6514 (5466–6966) / 0.61 / 43 | 6420 (6400–6525) / 0.80 / 51 | -0.17% / -23.75% | 1142 / 0.45 / 72.3% | 1193 / 0.43 / 71.2% | -4.27% / +4.65% |
| 聚焦 capacity,5 轮 | 6941 / 0.64 / 41 | 6527 / 0.82 / 50 | +6.34% / -21.95% | 1225 / 0.45 / 71.3% | 1297 / 0.45 / 69.9% | -6.67% / 0.00% |

capacity direct 锚点在两个引擎上均为 9404 Mbps。5 轮聚焦 TCP 的吞吐与 CPU
全部有利于 honk,配对 Mbps/core 提高 36.56%。完整 contract 含一个 honk
5466-Mbps 低值 arm,吞吐打平,但每轮 CPU 均更低,配对 Mbps/core 提高
30.93%。因此必须同时报告两种 contract：CPU 效率优势一致,不把 TCP 吞吐
概括为普遍胜出。

| 完整 contract 延迟 | honk | dae |
| --- | ---: | ---: |
| cold 中位数 | 3.040 ms | 3.958 ms |
| hot p50 / p95 | 0.839 / 1.949 ms | 0.739 / 1.214 ms |
| loaded Mbps | 6044 | 6045 |
| loaded p50 / p95 / p99 / max | 1.562 / 3.257 / 3.841 / 4.498 ms | 1.900 / 3.389 / 5.324 / 8.559 ms |
| loaded 失败 | 0 / 600 | 16 / 600 |

dae 的 hot-open 延迟更低；honk 的 cold 中位数更低,且在汇总中位负载实际相等
时,每轮 loaded tail 都更低。loaded 阶段位于容量边缘,不是等速率延迟对比。
饱和 UDP 在每轮聚焦配对中均有利于 dae；69–73% loss 来自刻意过载,不是 WAN
丢包结果,也不支持 honk UDP 增益。精确配置、raw row、loaded sample、hash 与
紧凑汇总位于
[`juicity-x86`](../bench/results/quic-analysis-2026-08-26/juicity-x86/)。

其他端到端候选均未能在一个稳定方向达到至少 3% 中位吞吐或 10% CPU
改善且不让另一方向回退,故未再开 performance PR。完整 hash、raw JSON、
profile、交替结果、聚焦测试证据及原样 runner 位于
[`quic-analysis-2026-08-26`](../bench/results/quic-analysis-2026-08-26/)。

## 结果(2026-08-25,Hysteria2 互操作与有界 QUIC GSO)

本轮以官方 Hysteria v2.12.2 服务端验证候选 `c1b8749`,并测量共享 QUIC
socket 改动。它补充而不替代下方 2026-08-24 honk/dae 配对基线。吞吐 fixture
使用明文 HY2/TUIC 与显式 **1452 字节 QUIC UDP payload**；不覆盖
Salamander、端口跳跃或 Juicity。

官方服务端矩阵覆盖 PKI 与证书 pin、自签名 TLS、Salamander、认证失败、
带宽提示、禁用 UDP 的明确拒绝、MTU/PMTUD/window、UDP 分片及公网端口
跳跃限制。见
[脱敏功能矩阵](../bench/results/quic-gso-2026-08-25/remote-hy2-feature-matrix.txt)。

### x86 有界 GSO 决策

两个启用 arm 与禁用 control 使用同一个最终 musl 二进制
(`dadefe68...`)及相同配置。control 以 `HONK_QUIC_GSO=0` 禁用 GSO；
启用 arm 不设置该变量,因此显式 1452 字节 payload 选择 GSO,应用层最多
16 个 segment。TCP 带宽单位为 Mbps,CPU 为核,RSS 为 MiB；loaded 单元格为
`Mbps / p99 ms / 200 次中的失败数`。

| 模式 | HY2 TCP / CPU / RSS | TUIC TCP / CPU / RSS | HY2 loaded | TUIC loaded |
| --- | ---: | ---: | ---: | ---: |
| 文档中的 2026-08-24 基线 | 6140 / 0.61 / 48 | 3350 / 0.34 / 43 | 6033 / 8.075 / 3 | 3366 / 2.609 / 0 |
| 最终二进制,GSO off | 6479 / 0.63 / 50 | 3273 / 0.33 / 42 | 6570 / 6.387 / 2 | 3335 / 2.574 / 0 |
| 最终二进制,GSO cap 16,arm A | 6845 / 0.63 / 55 | 3176 / 0.32 / 52 | 6568 / 3.879 / 0 | 3246 / 3.243 / 0 |
| 最终二进制,GSO cap 16,arm B | 6713 / 0.64 / 48 | 3264 / 0.31 / 43 | 6563 / 3.685 / 0 | 3199 / 2.328 / 4 |

相对同二进制 control,有界 GSO 将 HY2 TCP 容量提高 3.6–5.6%,同时 direct
锚点保持 9401–9406 Mbps。TUIC TCP 落在已知的 run-level 波动范围内,因此
不声称 TCP 加速。在刻意饱和的 10-Gbps UDP offer 下,HY2 从
831 Mbps / 81.1% loss 变为 902–935 Mbps / 77.3–78.6%；TUIC 从
814 / 80.3% 变为 979–1079 / 74.4–77.6%。这是过载容量结果,不是 WAN
丢包率。

启用时 HY2 RSS 为 48–55 MiB,TUIC 为 43–52 MiB；第二个 arm 回到文档基线
的 48/43 MiB。这排除了本样本中的持续 RSS 回退,并不等同于 allocation
计数结论。loaded 的稀疏失败随 arm 波动,表中原样保留而未取平均隐藏。

### ARM 探索性开关

ARM 板使用 pre-auto-GSO 候选及其已有 `HONK_QUIC_GSO=0|1` 开关,不是
最终 16-segment 二进制：

| 模式 | HY2 TCP / RSS；UDP | HY2 loaded Mbps / p99 / 失败 | TUIC TCP / RSS；UDP | TUIC loaded Mbps / p99 / 失败 |
| --- | ---: | ---: | ---: | ---: |
| GSO off | 345 / 39；2 Mbps (83.1%) | 344 / 125.828 / 0 | 245 / 25；3 Mbps (91.6%) | 257 / 37.010 / 0 |
| GSO on | 346 / 42；1 Mbps (84.7%) | 344 / 125.411 / 8 | 254 / 29；1 Mbps (92.4%) | 253 / 43.357 / 2 |

该板没有呈现 GSO 吞吐收益,启用 arm 的稀疏失败更多。本结果保留为板级
负面信号,不能证明最终 cap-16 的 ARM 性能。因此交付策略继续让抗黑洞的
1252 字节默认值使用 scalar send,仅在操作者选择更大 MTU 后启用有界 GSO,
并保留 `HONK_QUIC_GSO=0` 逃生开关。共享路径覆盖明文 HY2、TUIC 与 Juicity。
该 2026-08-25 arm 尚未接入 Juicity endpoint；上方当前 main 的专用对比现已
补齐该协议证据,且不改变这里的 GSO 决策。

完整 provenance、hash、TSV、loaded-run JSON/sample、探索性 arm 与清理状态
位于
[`quic-gso-2026-08-25`](../bench/results/quic-gso-2026-08-25/)。

## 结果(2026-08-24,当前跨架构配对 A/B)

这是当前配对轮：x86 `10.10.10.49` 与 ARM `10.10.10.118`。ARM 使用更新后的
kdae 配置(`eth0` 与 `disable_waiting_network: true`),kdae 版本为
`unstable-20260824.r1142.ec957346`。候选基于 main
`39f92eb51c62a9a330f56612c6671ae678a03585`;二进制、kernel、配置、harness
及结果 hash 以 [`metadata.txt`](../bench/results/cross-arch-2026-08-24/metadata.txt)
为准。

两种引擎均逐一运行,所有流量经过真实数据面。常规表为 3 次 cold、15 次
hot、3 次 8 秒带宽运行取中位数。loaded 表为同一路由上一条 reverse iperf3
负载下,每 250ms 发起一个请求,共 200 个。ARM 的 `lab` namespace holder
贯穿引擎 teardown/recreate,避免 honk 删除 `daens` 时客户端 namespace 消失。

### x86-64(`10.10.10.49`,4 vCPU / 2 GiB)

#### TCP 常规结果

延迟单位为 ms,带宽为 Mbps,CPU 为核数,RSS 为 MiB。

| 协议 | honk cold / hot p50 / hot p95 | dae cold / hot p50 / hot p95 | honk Mbps / 核 / RSS | dae Mbps / 核 / RSS | 带宽比 |
| --- | ---: | ---: | ---: | ---: | ---: |
| direct | 3.772 / – / – | 1.789 / – / – | 9403 / 0.00 / 46 | 9403 / 0.00 / 39 | 1.00× |
| hy2 | 1.627 / 0.870 / 2.347 | 3.060 / 0.719 / 0.930 | 6140 / 0.61 / 48 | 6466 / 0.79 / 51 | 0.95× |
| tuic | 1.708 / 0.795 / 3.429 | 18.096 / 16.352 / 16.921 | 3350 / 0.34 / 43 | 3877 / 0.52 / 54 | 0.86× |
| ss2022 | 3.310 / 1.174 / 1.385 | 2.080 / 1.083 / 2.241 | 9401 / 0.31 / 48 | 9368 / 0.37 / 53 | 1.00× |
| trojan | 5.320 / 0.891 / 7.515 | 2.208 / 1.381 / 2.961 | 9288 / 0.36 / 43 | 9381 / 0.44 / 46 | 0.99× |
| anytls-sb | 1.833 / 0.724 / 1.972 | 5.431 / 0.738 / 2.097 | 9361 / 0.43 / 46 | 9352 / 0.43 / 52 | 1.00× |
| anytls-go | 2.926 / 0.761 / 3.287 | 4.332 / 1.175 / 2.490 | 9391 / 0.47 / 42 | 9200 / 0.44 / 54 | 1.02× |

#### UDP 饱和

| 协议 | honk RTT ms | dae RTT ms | honk Mbps / loss / 核 | dae Mbps / loss / 核 | 带宽比 |
| --- | ---: | ---: | ---: | ---: | ---: |
| hy2 | 0.112 | 0.158 | 823 / 79.8% / 0.43 | 902 / 78.0% / 0.45 | 0.91× |
| tuic | 0.090 | 0.103 | 1049 / 75.3% / 0.47 | 937 / 76.7% / 0.48 | 1.12× |
| ss2022 | 0.079 | 0.154 | 1814 / 52.6% / 0.67 | 2513 / 34.3% / 0.64 | 0.72× |
| trojan | 0.112 | 0.070 | 1572 / 59.4% / 0.67 | 2870 / 23.7% / 0.60 | 0.55× |
| anytls-sb | 0.147 | 0.109 | 1156 / 68.0% / 0.43 | 1104 / 66.1% / 0.29 | 1.05× |
| anytls-go | 0.082 | 0.109 | 1299 / 64.7% / 0.48 | 1418 / 64.7% / 0.34 | 0.92× |

#### loaded 稳定性

percentile 只统计成功 HTTP 响应,失败数单列。

| 引擎 | 协议 | 负载 Mbps | p50 / p95 / p99 / max ms | 失败 |
| --- | --- | ---: | ---: | ---: |
| honk | direct | 9408 | 1.517 / 1.994 / 2.475 / 3.426 | 0/200 |
| honk | hy2 | 6033 | 1.708 / 3.005 / 8.075 / 9.802 | 3/200 |
| honk | tuic | 3366 | 1.400 / 2.061 / 2.609 / 2.767 | 0/200 |
| honk | ss2022 | 9403 | 1.885 / 3.177 / 4.869 / 6.013 | 4/200 |
| honk | trojan | 9323 | 1.671 / 4.362 / 7.895 / 11.469 | 0/200 |
| honk | anytls-sb | 9317 | 1.625 / 2.863 / 2089.764 / 3107.546 | 0/200 |
| honk | anytls-go | 9304 | 2.121 / 4.875 / 8.950 / 11.094 | 0/200 |
| dae | direct | 9406 | 1.687 / 2.306 / 2.551 / 4.937 | 0/200 |
| dae | hy2 | 6083 | 2.106 / 4.457 / 7.427 / 7.786 | 6/200 |
| dae | tuic | 4014 | 16.179 / 17.111 / 17.637 / 18.310 | 0/200 |
| dae | ss2022 | 9404 | 2.244 / 4.025 / 5.689 / 13.743 | 0/200 |
| dae | trojan | 9390 | 3.454 / 7.135 / 12.618 / 17.764 | 0/200 |
| dae | anytls-sb | 8770 | 1.626 / 3.889 / 42.709 / 58.435 | 4/200 |
| dae | anytls-go | 9244 | 2.278 / 11.220 / 16.807 / 20.968 | 2/200 |

x86 上,honk 的 SS2022、Trojan、sing-box AnyTLS 吞吐与 dae 相差不超过
1%,且所有 TCP 代理行 CPU 不高于 dae。HY2 慢 5%,TUIC 慢 14%,但 TUIC 热态
p95 为 3.429ms,明显低于 dae 的 16.921ms。UDP 结果混合：honk 只在 TUIC
和 sing-box AnyTLS 略占优,其余行落后。honk AnyTLS-sing-box 的 2.09 秒
p99 是原始样本中的真实离群值,没有删除。

### ARM64(`10.10.10.118`,NanoPi R2S / 1 GiB)

#### TCP 常规结果

| 协议 | honk cold / hot p50 / hot p95 | dae cold / hot p50 / hot p95 | honk Mbps / 核 / RSS | dae Mbps / 核 / RSS | 带宽比 |
| --- | ---: | ---: | ---: | ---: | ---: |
| direct | 3.544 / – / – | 3.379 / – / – | 862 / 0.02 / 22 | 860 / 0.01 / 41 | 1.00× |
| hy2 | 6.827 / 5.557 / 18.128 | 21.981 / 5.782 / 7.017 | 344 / 1.27 / 39 | 218 / 0.80 / 45 | 1.58× |
| tuic | 5.912 / 5.445 / 6.854 | 32.721 / 21.513 / 22.089 | 233 / 0.93 / 29 | 238 / 0.81 / 43 | 0.98× |
| ss2022 | 5.939 / 4.889 / 31.721 | 8.166 / 6.855 / 7.625 | 430 / 0.76 / 28 | 281 / 0.82 / 36 | 1.53× |
| trojan | 59.571 / 13.261 / 59.743 | 15.561 / 15.397 / 17.603 | 416 / 0.79 / 30 | 205 / 0.79 / 40 | 2.03× |

#### UDP 饱和

| 协议 | honk RTT ms | dae RTT ms | honk Mbps / loss / 核 | dae Mbps / loss / 核 | 带宽比 |
| --- | ---: | ---: | ---: | ---: | ---: |
| hy2 | 2.176 | 2.434 | 2 / 87.1% / 1.56 | 99 / 97.1% / 0.86 | 0.02× |
| tuic | 2.428 | 2.601 | 2 / 88.2% / 1.52 | 101 / 97.2% / 0.86 | 0.02× |
| ss2022 | 1.807 | 2.101 | 95 / 91.6% / 0.90 | 117 / 93.9% / 0.79 | 0.81× |
| trojan | 1.626 | 2.340 | 106 / 97.2% / 0.91 | 171 / 95.6% / 0.79 | 0.62× |

#### loaded 稳定性

| 引擎 | 协议 | 负载 Mbps | p50 / p95 / p99 / max ms | 失败 |
| --- | --- | ---: | ---: | ---: |
| honk | direct | 866 | 12.155 / 49.531 / 74.952 / 139.534 | 0/200 |
| honk | hy2 | 344 | 51.847 / 104.086 / 123.511 / 133.456 | 3/200 |
| honk | tuic | 263 | 21.895 / 32.327 / 39.561 / 58.102 | 0/200 |
| honk | ss2022 | 458 | 16.002 / 27.524 / 40.067 / 72.338 | 0/200 |
| honk | trojan | 392 | 11.988 / 21.573 / 31.547 / 73.303 | 0/200 |
| dae | direct | 524 | 8.907 / 50.834 / 84.706 / 91.599 | 0/200 |
| dae | hy2 | 216 | 35.539 / 56.397 / 74.111 / 74.429 | 8/200 |
| dae | tuic | 237 | 48.835 / 60.541 / 64.923 / 80.709 | 0/200 |
| dae | ss2022 | 279 | 14.374 / 20.924 / 24.875 / 47.538 | 0/200 |
| dae | trojan | 202 | 22.171 / 35.989 / 45.613 / 60.581 | 3/200 |

ARM 上,honk 的 TCP HY2、SS2022、Trojan 吞吐领先, TUIC 基本持平,且代理
RSS 全部更低。hot 尾延迟并非全面更好：TUIC 明显更低,HY2、SS2022、Trojan
更高。UDP 是本轮明确的 honk 回退：固定 10Gbps 供给下,HY2/TUIC 仅收到
2Mbps,dae 为 99/101Mbps；SS2022/Trojan 也落后。loaded 运行中 honk
失败更少(HY2 为 3 对 8,Trojan 为 0 对 3),但 HY2 与 SS2022 的 p99 更高。
这些是容量边缘结果,不是空载 WAN 延迟结论。

原始证据：[x86 常规 TSV](../bench/results/cross-arch-2026-08-24/x86-standard.tsv)、
[x86 loaded TSV](../bench/results/cross-arch-2026-08-24/x86-stability.tsv)、
[x86 raw](../bench/results/cross-arch-2026-08-24/x86-stability-raw/)、
[ARM 常规 TSV](../bench/results/cross-arch-2026-08-24/arm64-standard.tsv)、
[ARM loaded TSV](../bench/results/cross-arch-2026-08-24/arm64-stability.tsv)、
[ARM raw](../bench/results/cross-arch-2026-08-24/arm64-stability-raw/) 与
[输入文件](../bench/results/cross-arch-2026-08-24/arm64-inputs/)。

下面较早章节是历史记录,其中 `.45`/`.43` ARM 地址对应已替换的实验室主机；
当前 ARM 主机为上文的 `.118`。

## 结果(2026-08-08,x86-64 + ARM64 配对 A/B 与 loaded tail)

候选为基于 main `2e6d63a` 的当前 worktree；二进制、kernel、精确配置与
harness hash 以 [`metadata.txt`](../bench/results/cross-arch-2026-08-08/metadata.txt)
为准。两个候选都是 static musl、size-oriented release、默认 mimalloc。
常规表来自完整的 3 次 cold、15 次 hot、3×8s 带宽取中位数。loaded tail
另跑最终 fixed-cadence arm：同一路由有一条 self-saturating reverse TCP,
同时每 250ms 新开一条 HTTP stream,共 200 条。它测容量边缘,**不是等负载
延迟对比**；所以每个 percentile 旁都列出实际负载。探索阶段的串行 collector
在一次 timeout 后被确认会打乱节拍,其数据未发布。最终 raw run 的 p99
调度偏差最多 0.677ms,最大偏差 2.555ms。

原始证据：[x86 常规 TSV](../bench/results/cross-arch-2026-08-08/x86-standard.tsv)、
[x86 loaded TSV](../bench/results/cross-arch-2026-08-08/x86-stability.tsv)、
[x86 raw](../bench/results/cross-arch-2026-08-08/x86-stability-raw/) 与
[HY2/TUIC 复测](../bench/results/cross-arch-2026-08-08/x86-stability-repeat.tsv)。

### x86-64(`10.10.10.49`,4 vCPU / 2 GiB)

#### TCP 吞吐、CPU、内存与空载延迟

| 协议 | honk cold / hot p95(ms) | dae cold / hot p95(ms) | honk Mbps / 核 / RSS MiB | dae Mbps / 核 / RSS MiB | honk/dae 带宽 |
| --- | ---: | ---: | ---: | ---: | ---: |
| direct | 4.81 / – | 4.52 / – | 9404 / 0.00 / 50 | 9408 / 0.00 / 48 | 1.00× |
| hy2 | 2.47 / 1.92 | 31.73 / 1.83 | 5792 / 0.59 / 53 | 5046 / 1.09 / 66 | 1.15× |
| tuic | 2.36 / 1.82 | 80.64 / 78.61 | 6906 / 0.66 / 50 | 5065 / 1.02 / 65 | 1.36× |
| ss2022 | 3.50 / 11.92 | 7.45 / 6.62 | 9151 / 0.37 / 51 | 9259 / 0.42 / 54 | 0.99× |
| trojan | 6.40 / 6.08 | 7.04 / 16.78 | 9097 / 0.42 / 46 | 9100 / 0.64 / 58 | 1.00× |
| anytls-sb | 2.78 / 3.07 | 7.89 / 5.33 | 8532 / 0.46 / 46 | 7905 / 0.55 / 59 | 1.08× |
| anytls-go | 2.98 / 4.15 | 7.59 / 2.52 | 9105 / 0.49 / 53 | 9036 / 0.61 / 61 | 1.01× |

本机 TCP 结论：direct 完全持平；honk 的 HY2 +14.8%、TUIC +36.3%、
sing-box AnyTLS +7.9%,其余三项在 1.2% 内,而所有代理行的 engine CPU 都
更少。honk 代理行 RSS 为 46–53MiB,dae 为 54–66MiB。反例也必须保留：
honk 空载 SS2022 hot p95 为 11.92ms,dae 为 6.62ms；AnyTLS-Go 为
4.15ms 对 2.52ms；反过来 dae TUIC 热态仍约 79ms。

#### UDP 饱和

这里固定以 10Gbps 供给,高 `loss` 是预期饱和结果；应将接收 Mbps 与 loss
一起比较,不能把它解释为公网丢包率。

| 协议 | honk RTT ms | dae RTT ms | honk Mbps / loss / 核 | dae Mbps / loss / 核 | honk/dae 带宽 |
| --- | ---: | ---: | ---: | ---: | ---: |
| hy2 | 0.108 | 0.105 | 1490 / 58.9% / 0.84 | 828 / 79.8% / 0.72 | 1.80× |
| tuic | 0.158 | 0.134 | 1982 / 46.5% / 1.23 | 1922 / 49.8% / 1.48 | 1.03× |
| ss2022 | 0.222 | 0.184 | 1456 / 59.7% / 1.24 | 2675 / 30.1% / 1.64 | 0.54× |
| trojan | 0.135 | 0.099 | 1739 / 57.4% / 1.26 | 2916 / 24.3% / 1.59 | 0.60× |
| anytls-sb | 0.193 | 0.084 | 1194 / 69.1% / 0.73 | 1211 / 68.4% / 0.70 | 0.99× |
| anytls-go | 0.071 | 0.090 | 1249 / 66.2% / 0.79 | 1250 / 65.4% / 0.75 | 1.00× |

UDP 不是单边胜利：honk HY2 快 80%、TUIC 快 3%,两种 AnyTLS 持平；但
SS2022/Trojan 只达到 dae 的 54%/60%。

#### loaded 开流稳定性

percentile 只统计成功 HTTP 响应；失败数单列,因此 5s timeout 不会被低 p99
掩盖。

| 协议 | honk 负载 Mbps | honk p50 / p95 / p99 / max ms;失败 | dae 负载 Mbps | dae p50 / p95 / p99 / max ms;失败 |
| --- | ---: | --- | ---: | --- |
| direct | 9382 | 2.352 / 4.722 / 6.118 / 11.582; 0/200 | 9394 | 2.353 / 3.341 / 5.272 / 12.440; 0/200 |
| hy2 | 5597 | 2.391 / 3.359 / 6.095 / 16.981; 0/200 | 3465 | 3.195 / 13.755 / 176.642 / 399.369; 0/200 |
| tuic | 6197 | 2.683 / 6.694 / 16.031 / 16.927; 2/200 | 4848 | 77.108 / 82.733 / 87.135 / 88.816; 4/200 |
| ss2022 | 9319 | 2.573 / 5.011 / 17.161 / 18.311; 0/200 | invalid | invalid(3/3 load arm 中断) |
| trojan | 9300 | 2.272 / 4.873 / 12.416 / 17.280; 0/200 | 9124 | 5.940 / 18.994 / 23.151 / 31.855; 5/200 |
| anytls-sb | 8852 | 4.777 / 6.101 / 8.510 / 13.487; 0/200 | 8156 | 2.480 / 5.367 / 14.031 / 17.097; 3/200 |
| anytls-go | 9027 | 5.944 / 12.324 / 16.813 / 21.436; 0/200 | 9071 | 3.577 / 15.278 / 17.282 / 17.465; 1/200 |

dae SS2022 没有被强行换算成 percentile：三次 55s arm 都在 30s 丢失
iperf control connection,错误均为 `control socket has closed unexpectedly`。
中断前负载为 9.07–9.35Gbps；三轮 HTTP 失败分别为 0/200、5/200、0/200。
这是可复现的长流稳定性失败,不是吞吐为零。

因为一个 x86 arm 出现明显的整轮 tail,又对 HY2/TUIC 做了复测：

| 引擎 / 协议 | fixed-cadence arm A:负载 / p99 / 失败 | arm B:负载 / p99 / 失败 |
| --- | --- | --- |
| honk / hy2 | 5597Mbps / 6.095ms / 0/200 | 5104Mbps / 7.225ms / 1/200 |
| honk / tuic | 6197Mbps / 16.031ms / 2/200 | 6078Mbps / 8.048ms / 0/200 |
| dae / hy2 | 3465Mbps / 176.642ms / 0/200 | 5323Mbps / 11.284ms / 0/200 |
| dae / tuic | 4848Mbps / 87.135ms / 4/200 | 4603Mbps / 81.657ms / 0/200 |

honk HY2 两轮 p99 保持 6.1–7.2ms；dae HY2 在两轮间呈双峰。TUIC 持续分离：
honk 8.0–16.0ms,dae 81.7–87.1ms p99。双方都有稀疏失败(每轮 0–1%),
不能把这些样本外推为长期失败率。

### ARM64(`10.10.10.45`,NanoPi R2S / 1 GiB)

ARM 配对表只列该 dae build 也支持的四协议。原始证据：
[常规](../bench/results/cross-arch-2026-08-08/arm64-standard.tsv)、
[loaded](../bench/results/cross-arch-2026-08-08/arm64-stability.tsv)、
[raw](../bench/results/cross-arch-2026-08-08/arm64-stability-raw/) 与
[复测](../bench/results/cross-arch-2026-08-08/arm64-stability-repeat.tsv)。
所有已发布且有效的 ARM arm 中，最坏 p99 调度偏差为 17.390ms，单次最大
发起偏差为 41.592ms，仍远小于 250ms 发起间隔。

#### TCP 吞吐、CPU、内存与空载延迟

| 协议 | honk cold / hot p95(ms) | dae cold / hot p95(ms) | honk Mbps / 核 / RSS MiB | dae Mbps / 核 / RSS MiB | honk/dae 带宽 |
| --- | ---: | ---: | ---: | ---: | ---: |
| direct | 6.66 / – | 6.63 / – | 889 / 0.00 / 57 | 899 / 0.01 / 42 | 0.99× |
| hy2 | 10.43 / 11.13 | 38.96 / 8.30 | 269 / 1.33 / 61 | 189 / 1.84 / 60 | 1.42× |
| tuic | 12.35 / 9.77 | 109.89 / 84.80 | 262 / 1.35 / 53 | 197 / 1.79 / 51 | 1.33× |
| ss2022 | 15.76 / 8.15 | 10.57 / 13.07 | 350 / 0.87 / 57 | 252 / 0.87 / 43 | 1.39× |
| trojan | 16.22 / 16.28 | 39.12 / 19.46 | 279 / 0.88 / 49 | 173 / 0.78 / 44 | 1.61× |

direct 是链路上限下持平。四个共有代理协议上,honk TCP 多 33–61%；HY2
少用 28% CPU,TUIC 少 25%,SS2022 CPU 持平,Trojan 多 13%。与 x86 不同,
ARM 内存不是 honk 优势：代理行 RSS 49–61MiB,dae 为 43–60MiB。空载延迟
也有取舍：honk 的 TUIC/SS2022/Trojan hot p95 更低,dae 的 HY2 更低。

#### UDP 饱和

| 协议 | honk RTT ms | dae RTT ms | honk Mbps / loss / 核 | dae Mbps / loss / 核 | honk/dae 带宽 |
| --- | ---: | ---: | ---: | ---: | ---: |
| hy2 | 2.921 | 3.121 | 35 / 97.3% / 1.84 | 29 / 97.3% / 2.15 | 1.21× |
| tuic | 2.675 | 3.513 | 54 / 97.9% / 1.76 | 31 / 94.1% / 2.20 | 1.74× |
| ss2022 | 2.021 | 2.581 | 35 / 71.8% / 0.92 | 39 / 89.4% / 1.29 | 0.90× |
| trojan | 2.366 | 2.675 | 32 / 96.5% / 0.86 | 49 / 97.0% / 1.47 | 0.65× |

换到 ARM 没有改变 x86 的 UDP 分裂：honk 的 HY2/TUIC 更快,dae 的
SS2022/Trojan 更快。绝对值是 A53/USB 网卡饱和结果,不是公网预期。

#### loaded 开流稳定性

| 协议 | honk 负载 Mbps | honk p50 / p95 / p99 / max ms;失败 | dae 负载 Mbps | dae p50 / p95 / p99 / max ms;失败 |
| --- | ---: | --- | ---: | --- |
| direct | 877 | 13.263 / 16.429 / 253.604 / 2040.151; 0/200 | 896 | 12.817 / 22.490 / 240.131 / 1032.783; 0/200 |
| hy2 | 267 | 75.391 / 144.587 / 171.303 / 209.632; 0/200 | 188 | 45.731 / 84.419 / 104.706 / 120.980; 1/200 |
| tuic | 261 | 30.032 / 67.089 / 78.956 / 137.535; 0/200 | 191 | 104.555 / 114.873 / 120.645 / 124.333; 0/200 |
| ss2022 | 356 | 17.586 / 31.881 / 41.419 / 192.975; 0/200 | invalid | invalid(3/3 load arm 中断) |
| trojan | 293 | 14.632 / 30.428 / 38.831 / 39.198; 1/200 | 173 | 23.968 / 29.960 / 36.468 / 52.650; 0/200 |

direct 对照说明 ARM tail 必须结合负载看：两个引擎在约 0.9Gbps 时 p99
都约 240–254ms,最大超过 1s,但 engine CPU 近零；瓶颈是饱和 host/USB
路径。HY2 是容量/延迟取舍：honk 多 42% 吞吐,dae 在更低负载下 self-
saturated p99 更低。TUIC 更明确偏向 honk：负载多 37% 且 p99 更低。
Trojan p99 基本持平,但 honk 负载多 69%。

定向复测的负载稳定,同时暴露了整轮失败数的变化：

| 引擎 / 协议 | arm A:负载 / p99 / 失败 | arm B:负载 / p99 / 失败 |
| --- | --- | --- |
| honk / hy2 | 267Mbps / 171.303ms / 0/200 | 269Mbps / 164.253ms / 5/200 |
| honk / tuic | 261Mbps / 78.956ms / 0/200 | 260Mbps / 114.847ms / 0/200 |
| dae / hy2 | 188Mbps / 104.706ms / 1/200 | 188Mbps / 87.126ms / 0/200 |
| dae / tuic | 191Mbps / 120.645ms / 0/200 | 193Mbps / 118.337ms / 0/200 |

dae SS2022 与 x86 完全复现：每个 load arm 都在 30s 以
`control socket has closed unexpectedly` 结束。中断前为 246–260Mbps；
三次 HTTP 失败为 0/200、5/200、6/200。相同时间点和错误跨架构重现,
说明这是 dae 长流生命周期结果,不是 host 噪声。

### honk-only AnyTLS 与 rprx 覆盖

ARM dae build 没有 AnyTLS/rprx handler,所以下表不标成 A/B 胜利。专用
rprx 配置复用实际在线的 `8001-8003` / `5201-5203` 目标；原先预留的
`8007-8009` / `5207-5209` 未启动,对应探索数据已丢弃。VLESS/VMess 没有
UDP 实现；归档中的空值/`0(-)` UDP 字段代表 capability N/A,不是回退或
性能退化,修正后的 harness 会显式输出 `n/a`。

原始证据：[ARM AnyTLS](../bench/results/cross-arch-2026-08-08/arm64-honk-anytls.tsv)、
[ARM AnyTLS loaded](../bench/results/cross-arch-2026-08-08/arm64-honk-anytls-stability.tsv)、
[ARM AnyTLS raw](../bench/results/cross-arch-2026-08-08/arm64-honk-anytls-stability-raw/)、
[ARM rprx](../bench/results/cross-arch-2026-08-08/arm64-honk-rprx.tsv)、
[ARM rprx loaded](../bench/results/cross-arch-2026-08-08/arm64-honk-rprx-stability.tsv)、
[ARM rprx raw](../bench/results/cross-arch-2026-08-08/arm64-honk-rprx-stability-raw/)、
[x86 rprx](../bench/results/cross-arch-2026-08-08/x86-honk-rprx.tsv)、
[x86 rprx loaded](../bench/results/cross-arch-2026-08-08/x86-honk-rprx-stability.tsv) 与
[x86 rprx raw](../bench/results/cross-arch-2026-08-08/x86-honk-rprx-stability-raw/)。

| 协议 | x86 cold / hot p95 ms; Mbps / 核 | ARM cold / hot p95 ms; Mbps / 核 | x86 loaded Mbps / p99 / 失败 | ARM loaded Mbps / p99 / 失败 |
| --- | --- | --- | --- | --- |
| anytls-sb | 2.78 / 3.07; 8532 / 0.46 | 9.08 / 7.20; 324 / 0.97 | 8852 / 8.510ms / 0/200 | 336 / 168.274ms / 0/200 |
| anytls-go | 2.98 / 4.15; 9105 / 0.49 | 8.24 / 8.55; 313 / 0.96 | 9027 / 16.813ms / 0/200 | 318 / 515.541ms / 0/200 |
| vless-vision | 4.88 / 4.03; 9372 / 0.60 | 23.47 / 20.23; 154 / 0.71 | 9353 / 16.677ms / 0/200 | 168 / 39.023ms / 8/200 |
| vless-reality | 4.69 / 8.03; 9367 / 0.45 | 17.78 / 13.48; 282 / 0.87 | 9320 / 16.910ms / 0/200 | 274 / 53.338ms / 0/200 |
| vmess | 2.33 / 2.35; 9373 / 0.51 | 9.42 / 7.88; 342 / 1.29 | 7789 / 48.780ms / 0/200 | 335 / 37.198ms / 0/200 |

x86 三项 rprx 的常规吞吐都为 9.37Gbps；VMess 在 50s 混合负载中降到
7.79Gbps,p99 升到 48.8ms。ARM 上 Vision 是明显异常项：154Mbps,loaded
时有 8 个聚集的 5s HTTP timeout。Reality 和 VMess 无失败。AnyTLS-Go
的 ARM p99 515ms 来自小段长尾(p50 156ms,max 1.006s),不是失败请求。

### 跨架构决策

- **TCP 容量**：honk 在 ARM 四个共有协议上领先 33–61%；x86 除 SS2022
  (-1.2%)外领先或持平；direct 持平。
- **效率**：honk 在全部 x86 代理行以及 ARM HY2/TUIC 上 CPU 更少；ARM
  Trojan 与内存是反例,所以不能泛化。
- **延迟稳定性**：x86 总体偏向 honk,尤其 TUIC,但仍观察到稀疏 timeout。
  ARM 与负载相关：dae HY2 在低 30% 负载下 tail 更低；honk TUIC 则负载
  更高且 tail 更低。只按吞吐或只按 p99 排名都不诚实。
- **UDP**：两个架构上 honk 都赢 HY2/TUIC、输 SS2022/Trojan。
- **长流失败**：dae SS2022 的 30s control closure 在每台机器都 3/3
  复现,是矩阵里最强的稳定性缺陷。
- **资源适配**：x86 honk 节省 RSS,1GiB R2S 上则没有。rprx 在 x86
  line-rate；Vision 的 ARM 吞吐与 4% 样本 timeout 率仍需改进,不能称为
  饱和负载下 gateway-safe。

## 结果(2026-08-06,UDP post-decision 卸载验证轮 @ NanoPi R2S)

验证 UDP QUIC 卸载(drop-and-reinject 重构版,`HONK_UDP_POST_DECISION_OFFLOAD=1`)。
标准 UDP 行(iperf3/echo,代理协议组)不受此功能影响——数值与上轮逐行吻合
(噪声内)即为正确结果;另增 QUIC 型 direct UDP 负载补测(juicity 隧道穿
`domain(suffix:hy2.test)->direct`,domain++):

| 负载 | 卸载开 | 卸载关 |
| --- | --- | --- |
| QUIC direct UDP(juicity) | **149.1 Mbps @ 0.00 核**(endpoint hits=0) | 33.2 Mbps @ 0.78 核(hits=13588) |

吞吐 4.5×、引擎 CPU 归零(149Mbps 上限来自 juicity 客户端自身在 A53 上的
QUIC crypto)。direct 行保持 874 Mbps @ 0.00 核(dae 889 持平),TCP 协议行
偏差 ≤2.3% 无回归。

## 结果(2026-08-06,direct 内核卸载验证轮 @ NanoPi R2S)

验证 PR #17(Rule 模式 direct 流全量内核卸载,按流缓存决策,零每包开销)。
引擎为 feat/rprx(含 main `ac5ffbb`)aarch64 musl,lab 的 8080/5300 目标走
`fallback: direct`(非 must)——正是本功能的目标路径。两轮交替,dae 同窗口
重测。

| 引擎 | 协议 | cold | bw (Mbps) | cpu | RSS |
| --- | --- | --- | --- | --- | --- |
| honk | direct(卸载后) | 0.0043 | **880**(上轮 370) | **0.01**(上轮 0.71) | 61 |
| dae | direct | 0.0041 | 896 | 0.01 | 39 |

协议行两轮全部在上轮噪声内(hy2 267/268、tuic 260/262、ss2022 353/353、
trojan 279/282),无回归。honk direct 与 dae 同量级(差距 1.8% 属链路噪声),
cold 同步改善(6.2→4.3ms,与 dae 4.1ms 持平)。

## 结果(2026-08-05,ARM A/B: honk vs dae @ NanoPi R2S)

双引擎对照轮,引擎机 NanoPi R2S(两轮:.43 板载网口 / .45 USB 网卡复测),
honk 为 feat/rprx `2ad0a93` aarch64 musl,dae 为 kdae `ae056a6a`(go1.26.5)。
方法学不变;两引擎同一时刻只跑一个。dae 仅支持共有协议行(hy2/tuic/
ss2022/trojan)。两轮交替取均值,轮内偏差 <5%。**注意 .45 复测用 USB 网卡,
绝对带宽整体下移 ~10–15%,引擎间比值才是可比项。**

### TCP(.45 复测值;`→` 后为 .43 首轮值)

| 引擎 | 协议 | cold | hot p50 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0062 | – | 370 →458 | 0.71 | 52 |
| dae | direct | 0.0057 | – | 895 →931 | 0.01 | 39 |
| honk | hy2 | 0.0091 | 0.0081 | 268 →303 | 1.34 | 59 |
| dae | hy2 | 0.0367 | 0.0079 | 191 →197 | 1.86 | 57 |
| honk | tuic | 0.0070 | 0.0070 | 262 →293 | 1.36 | 59 |
| dae | tuic | 0.1040 | 0.0834 | 196 →208 | 1.80 | 49 |
| honk | ss2022 | 0.0070 | 0.0058 | 353 →385 | 0.88 | 51 |
| dae | ss2022 | 0.0114 | 0.0092 | 247 →265 | 0.87 | 41 |
| honk | trojan | 0.0221 | 0.0061 | 282 →328 | 0.88 | 53 |
| dae | trojan | 0.0228 | 0.0163 | 171 →201 | 0.78 | 42 |

### UDP(.45 复测值;echo RTT 秒 / 饱和接收 Mbps / cpu)

| 引擎 | 协议 | RTT | bw | cpu |
| --- | --- | --- | --- | --- |
| honk | hy2/udp | 0.0029 | 33 | 1.85 |
| dae | hy2/udp | 0.0034 | 31 | 2.14 |
| honk | tuic/udp | 0.0028 | 53 | 1.76 |
| dae | tuic/udp | 0.0034 | 33 | 2.21 |
| honk | ss2022/udp | 0.0021 | 34 (73.8%) | 0.93 |
| dae | ss2022/udp | 0.0027 | 40 (87.9%) | 1.29 |
| honk | trojan/udp | 0.0019 | 31 | 0.88 |
| dae | trojan/udp | 0.0031 | 49 | 1.45 |

解读:

- **honk TCP 吞吐领先 35–65% 且可复现**:hy2 1.40×、tuic 1.34×、trojan
  1.65×、ss2022 1.43×(与 .43 轮比值漂移 ≤0.1);每 Mbps 的 CPU 成本约为
  dae 的一半(hy2: 1.34 核@268 vs 1.86 核@191)。A53 弱核上 Go 运行时的
  每字节成本在 QUIC 协议上被放大得最厉害。
- **延迟**:dae tuic 热 p50 83ms/冷 104ms(每连接重建 QUIC 会话)两轮原样
  重现;honk 全协议热 p50 ≤8ms。UDP echo RTT honk 各行稳定低 0.5–1.2ms。
- **direct 行差异是路径而非引擎**:dae 把 fallback direct 全量 eBPF 卸载
  (895Mbps@0.01 核),honk 只对 must 标记的 direct 卸载,fallback direct
  走用户态 relay(370@0.71)——可作 honk 后续优化点。
- **UDP** 两引擎都触及 A53 平台瓶颈(30–57Mbps),互有胜负;内存 dae 略省
  (38–59MB vs 48–61MB),1GB 设备上均非约束。
- 公平性:双方 TCP relay 均在用户态(dae 日志确认 eBPF offload 关闭)。

## 结果(2026-08-05,ARM 轮: NanoPi R2S / RK3328)

引擎机 10.10.10.43(NanoPi R2S: 4×Cortex-A53 @1.3GHz, 968MB RAM, end0
1Gbps, kernel 6.18, cpuinfo 含 `aes pmull sha1 sha2`),引擎为 feat/rprx
`2ad0a93` aarch64 musl 构建。方法学不变(netns lab → 真实 eBPF 数据面 →
.70)。**线速锚点: 关闭引擎后 netns+NAT 路径打满 941 Mbps**,以下数字的
瓶颈全在引擎用户态。CPU 列仅含 honk 进程 utime/stime,不含 softirq。

### TCP

| 引擎 | 协议 | cold | hot p50 | hot p95 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0064 | – | – | 437 | 0.74 | 50 |
| honk | hy2 | 0.0100 | 0.0084 | 0.0090 | 301 | 1.34 | 61 |
| honk | tuic | 0.0097 | 0.0073 | 0.0082 | 304 | 1.33 | 56 |
| honk | ss2022 | 0.0105 | 0.0057 | 0.0065 | 388 | 0.83 | 55 |
| honk | trojan | 0.0213 | 0.0060 | 0.0205 | 329 | 0.91 | 50 |
| honk | anytls-sb | 0.0066 | 0.0061 | 0.0065 | 336 | 0.98 | 51 |
| honk | anytls-go | 0.0116 | 0.0065 | 0.0076 | 337 | 0.96 | 51 |
| honk | vless-reality-vision | 0.0225 | 0.0181 | 0.0196 | 183 | 0.74 | 51 |
| honk | vless-reality | 0.0208 | 0.0174 | 0.0287 | 332 | 0.88 | 52 |
| honk | vmess (tcp) | 0.0076 | 0.0067 | 0.0087 | 416 | 1.50 | 47 |

### UDP(热态,`udp_warm_node_count: 8`)

| 协议 | echo RTT p50 | bw Mbps (loss) | cpu |
| --- | --- | --- | --- |
| hy2 | 2.77 ms | 34 (97.8%) | 1.91 |
| tuic | 2.88 ms | 46 (98.1%) | 1.86 |
| ss2022 | 2.09 ms | 42 (91.0%) | 0.92 |
| trojan | 2.12 ms | 38 (98.1%) | 0.90 |
| anytls-sb | 2.23 ms | 50 (89.3%) | 1.79 |
| anytls-go | 2.54 ms | 57 (87.7%) | 1.80 |

解读(A53 小核 vs x86 E-13600K,同方法学对照 08-04 轮):

- **全部 CPU-bound**:direct 437(x86 9390);TCP 类被压平在 330–390
  Mbps(行间扁平 = 瓶颈在公共 relay+crypto 路径);QUIC 每核效率差 ~20 倍。
  vmess 416 最接近 direct 基线,印证 `5dc47cf` 的 BoringSSL AEAD 在 ARM
  crypto extensions 下同样有效;其 cpu 1.50 仍是 TCP 类最高(跨平台共同
  优化点)。vless-vision 183 为 TCP 最低行;vision/reality 行 hot p50
  ~18ms(x86 3.3ms)是 REALITY 握手在慢 crypto 上的每连接成本。
- **UDP 是重灾区**:34–57 Mbps、丢包 88–98%——A53 上逐包路径(TPROXY
  recvmsg provenance + anyfrom 回复 + 隧道组帧)完全饱和,echo RTT 比
  x86 慢一个量级。
- **RSS 47–61MB 与 x86 相同**,1GB 设备全程无内存压力——瓶颈纯 CPU。
- rprx 行的 .70 目标服务(8007-8009/5207-5209/53537-53539)本轮处于半坏
  状态,三行用等价变体(工作目标 8001/5201 重路由到对应 group)测量,
  方法学不变。

## 结果(2026-08-05,rprx 协议族: VLESS+REALITY(±vision)/VMess 入列)

本轮覆盖 feat/rprx(PR #12)新增的协议行,引擎为 feat/rprx musl+mimalloc 构建
(vless 行于 `67b5a56` 测量,vmess 行在 `5dc47cf` AEAD 修复后重建测量;修复
内容见该分支)。方法学与上文完全一致。新增服务端矩阵(10.10.10.70,sing-box
1.13.14):vless+reality+vision `:2448`、vless+reality `:2449`、vmess 裸 tcp
`:2450`;目标服务 http `8007-8009`、iperf3 `5207-5209`、udp echo
`53537-53539`;引擎按端口路由(`5207/8007/53537→vision`、`…8→reality`、
`…9→vmess`)。reality 伪装目标为本地 TLS 服务(注意:dest 的 TLS Certificate
消息必须 <8KiB,否则 reality 服务端的 CH 缓存放不下会判定失败)。

校准锚点(本轮 vs 08-04 轮):direct 9411/9390、ss2022 9399/9398、
anytls-sb 9406/9388 Mbps——环境判定一致,下表可直接与 08-04 轮横向比较。

| 引擎 | 协议 | cold | hot p50 | hot p95 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | vless-reality-vision | 0.0037 | 0.0033 | 0.0050 | 9372 | 0.60 | 45 |
| honk | vless-reality | 0.0043 | 0.0034 | 0.0042 | 9383 | 0.49 | 54 |
| honk | vmess (tcp) | 0.0022 | 0.0010 | 0.0014 | 9313 | 0.78 | 50 |

- 三行全部贴线速(~9.4G)。vmess 行是 `5dc47cf`(body AEAD 从 RustCrypto
  切到 BoringSSL)之后的结果;修复前同路径 handler 级测量仅 ~420 MB/s
  (单核 105%)。vmess cpu 0.78 核仍是 TCP 类协议中最高(每 chunk 的
  SHAKE 长度掩码 + 帧处理),可作后续优化点。
- vision vs 无 vision 无带宽差异(10G 内非 vision 的 BoringSSL AES-NI 已
  贴线速);vision 行 cpu 略高(0.60 vs 0.49)为组帧开销,cold 含 reality
  握手。
- vless/vmess 在 honk 无 UDP 数据面(README TODO),UDP 行无数据,非测量
  失败。

## 结果(2026-08-04,honk outbound-v2 重构回归验证)

本轮是 outbound-v2 重构合并的单引擎回归验证,不含 dae/sing-box 对照臂;
对照基线为 08-02 轮(`49b166d`)。引擎机 10.10.10.59,服务端 10.10.10.70,
测量方法不变。

- honk: main `d00cb5e`(musl, mimalloc)——outbound-v2 重构(协议面收缩为
  Direct/Block/SOCKS5/SS2022/Trojan/VMess/VLess/AnyTLS/Hysteria2/TUIC/Juicity;
  `ProtocolDescriptor` 能力表;能力 trait 取代大接口 `ProxyHandler`;内容派生
  稳定 NodeId;QUIC client 归 generation 所有且未变节点跨 reload 复用;TCP 拨号
  路径固定准入 generation;拨号预算 per-generation),外加下述 AnyTLS 溢出修复。

**本轮抓到一个 main 上的真实回归。** `85d6b61`(限制慢消费者溢出,已随
v0.0.1.beta.33/34 发布)在流溢出达到 2 MiB 上限的瞬间即 reset——但快 LAN
对端约 4ms 就能 burst 超过这个量,此时 reader 任务尚未被首次调度,于是单流
iperf3 在重构前(`8a32149`)与重构后的二进制上都只有 2–3 Mbps(bisect 确认:
父提交 `c7cbd67` 正常,8.8 Gbps)。修复(`caa95b0` + `d00cb5e`)恢复基于进展的
语义:流字节上限在 3 秒无 flush 进展宽限内为软上限——parked 字节不等于停滞;
session 级上限触顶时 demux 以 500ms 轮次等待 reader 进展(暂停读取借 TCP 窗口
施加背压),超时的轮次只 reset 最停滞的 parked 流。实验室验证:anytls-sb 9388 /
anytls-go 9396 Mbps,零溢出误杀,relay 计数器确认走隧道。

### TCP

| 引擎 | 协议 | cold | hot p50 | hot p95 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0022 | – | – | 9390¹ | 0.27 | 54 |
| honk | hy2 | 0.0024 | 0.0011 | 0.0020 | 6156 | 1.03 | 56 |
| honk | tuic | 0.0024 | 0.0013 | 0.0019 | 5293 | 0.71 | 54 |
| honk | ss2022 | 0.0019 | 0.0013 | 0.0016 | 9398 | 0.37 | 54 |
| honk | trojan | 0.0046 | 0.0010 | 0.0034 | 9377 | 0.47 | 50 |
| honk | anytls-sb | 0.0025 | 0.0012 | 0.0015 | 9388 | 0.47 | 51 |
| honk | anytls-go | 0.0023 | 0.0013 | 0.0017 | 9396 | 0.49 | 50 |

### UDP(热态,`udp_warm_node_count: 8`)

| 引擎 | 协议 | echo RTT p50 | bw Mbps (loss) | cpu |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.12 ms | 1814 (72.7%) | 1.25 |
| honk | tuic | 0.37 ms | 58 (68.6%)² | 0.07 |
| honk | ss2022 | 0.15 ms | 1889 (68.7%) | 1.32 |
| honk | trojan | 0.06 ms | 1394 (79.7%) | 1.08 |
| honk | anytls-sb | 0.07 ms | 1370 (77.4%) | 0.92 |
| honk | anytls-go | 0.22 ms | 1735 (71.7%) | 1.24 |

¹ direct 行首次读数 6841 处于实验室负载窗口;随后三次复测为 9388/9389/9390。
² 本轮 TUIC UDP 对所有引擎都塌陷——.70→.59 UDP 链路接近饱和(与 08-02 轮
相同的实验室条件 artifact),非引擎回归。

### 08-04 结果解读

- **重构无回归**:与当天重构前对照臂(`8a32149`)相比,非 AnyTLS 行全部在
  实验室波动内持平(hy2 6156 vs 5966,tuic 5293 vs 5546,ss2022/trojan 双双
  线速)。相对 08-02 轮的更高读数(hy2 2858、tuic 4134)来自空闲实验室,而非
  重构提速——QUIC 数据面代码未变。
- **AnyTLS 是最大收益**:停滞宽限修复把 anytls-sb 从回归前基线 4575 提到 9388
  (线速),anytls-go 到 9396——demux 背压设计同时消除了旧 park 路径在快对端下
  的溢出抖动。重构前二进制两行均只有 2–3 Mbps(bug 存在)。
- TUIC UDP 仍是已知弱点(见上实验室链路说明)。

## 结果(2026-08-02,三引擎:honk vs dae vs sing-box)

本轮引擎机为 **10.10.10.59**(同实验室的另一台 VM,服务端仍为物理机
10.10.10.70;生产网关 10.10.10.1 已加 `sip(10.10.10.59/32) -> direct(must)`
规则,基准流量不经过网关代理面)。配置与测量方法与 08-01 轮一致。

- honk: main `49b166d`(musl, mimalloc)——含 eBPF 数据面准入门、LB/Fallback
  按 TCP/UDP 分离、AnyTLS TLS connector 懒加载、日志短路修复、拨号失败罚样本、
  TPROXY listener 标记、URLTest 减半递推移动平均。
- dae: kdae `ae056a6a`(Go 1.26.0;自 08-01 轮的 `eee7c88b` 更新,含 outbound
  fork 修复)。
- sing-box: v1.13.14(lab netns 内 TUN 客户端,按端口路由)。

延迟单位秒,TCP 带宽为 iperf3 接收端中位数,CPU 单位核,RSS 为跑后值。

### TCP

| 引擎 | 协议 | cold | hot p50 | hot p95 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0082 | – | – | 9399 | 0.26 | 54 |
| dae | direct | 0.0034 | – | – | 9402 | 0.00 | 50 |
| sing-box | direct | 0.0052 | – | – | 9403 | 0.43 | 47 |
| honk | hy2 | 0.0060 | 0.0034 | 0.0047 | 2858 | 0.49 | 59 |
| dae | hy2 | 0.0104 | 0.0032 | 0.0036 | 2757 | 0.82 | 61 |
| sing-box | hy2 | 0.0108 | 0.0039 | 0.0053 | 2570 | 0.87 | 51 |
| honk | tuic | 0.0060 | 0.0037 | 0.0054 | 4134 | 0.59 | 54 |
| dae | tuic | 0.0858 | 0.0797 | 0.0804 | 2940 | 0.82 | 62 |
| sing-box | tuic | 0.0083 | 0.0039 | 0.0051 | 2618 | 0.89 | 51 |
| honk | ss2022 | 0.0052 | 0.0036 | 0.0061 | 9333 | 0.39 | 57 |
| dae | ss2022 | 0.0041 | 0.0041 | 0.0049 | 9372 | 0.51 | 53 |
| sing-box | ss2022 | 0.0057 | 0.0041 | 0.0069 | 9342 | 1.30 | 51 |
| honk | trojan | 0.0113 | 0.0023 | 0.0107 | 9244 | 0.46 | 50 |
| dae | trojan | 0.0104 | 0.0075 | 0.0106 | 9162 | 0.71 | 55 |
| sing-box | trojan | 0.0098 | 0.0090 | 0.0124 | 9187 | 0.86 | 49 |
| honk | anytls-sb | 0.0055 | 0.0043 | 0.0061 | 4575 | 0.30 | 50 |
| dae | anytls-sb | 0.0089 | 0.0037 | 0.0047 | 4522 | 0.40 | 56 |
| sing-box | anytls-sb | 0.0131 | 0.0035 | 0.0053 | 4512 | 0.50 | 48 |
| honk | anytls-go | 0.0052 | 0.0032 | 0.0049 | 8937 | 0.54 | 52 |
| dae | anytls-go | 0.0080 | 0.0038 | 0.0049 | 8892 | 0.69 | 61 |
| sing-box | anytls-go | 0.0113 | 0.0039 | 0.0046 | 8741 | 1.05 | 48 |

### UDP (iperf3 `-u -b 10G -l 1200 -R`)

| 引擎 | 协议 | echo RTT p50 | bw Mbps (丢包) | cpu |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.20 ms | 1743 (71.5%) | 1.16 |
| dae | hy2 | 0.22 ms | 931 (85.5%) | 0.95 |
| sing-box | hy2 | 0.33 ms | 1561 (75.0%) | 1.41 |
| honk | tuic | 0.20 ms | 1577 (70.6%) | 1.33 |
| dae | tuic | 0.33 ms | 108 (76.2%) | 0.13 |
| sing-box | tuic | 0.30 ms | 27 (80.9%) | 0.05 |
| honk | ss2022 | 0.20 ms | 1207 (78.6%) | 1.23 |
| dae | ss2022 | 0.13 ms | 2367 (58.6%) | 1.76 |
| sing-box | ss2022 | 0.17 ms | 2509 (55.6%) | 1.34 |
| honk | trojan | 0.10 ms | 1629 (70.1%) | 1.28 |
| dae | trojan | 0.18 ms | 2903 (49.5%) | 1.67 |
| sing-box | trojan | 0.13 ms | 3330 (41.6%) | 1.66 |
| honk | anytls-sb | 0.23 ms | 1287 (79.2%) | 0.91 |
| dae | anytls-sb | 0.26 ms | 1290 (77.9%) | 0.91 |
| sing-box | anytls-sb | 0.36 ms | 1262 (79.1%) | 1.18 |
| honk | anytls-go | 0.24 ms | 1539 (75.6%) | 1.10 |
| dae | anytls-go | 0.22 ms | 1493 (76.0%) | 1.01 |
| sing-box | anytls-go | 0.18 ms | 1368 (77.7%) | 1.24 |

### UDP:预热稳态三引擎对比(08-02)

方法同 08-01 稳态轮:每引擎启动后等 30s 健康检查收敛,各协议 5 次 TCP 预热,
静置 10s 后测量。`iperf3 -u -b 10G -l 1200 -R` 单流与 `-P 8` 聚合。

| 引擎 | 协议 | echo RTT (ms) | 单流 Mbps(丢包) | P8 聚合 Mbps(丢包) |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.22 | 1663 (73.8%) | 1582 (95.8%) |
| dae | hy2 | 0.36 | 938 (85.6%) | 864 (97.6%) |
| sing-box | hy2 | 0.42 | 1607 (74.4%) | 1588 (95.7%) |
| honk | tuic | 0.11 | 359 (67.1%) | FAIL |
| dae | tuic | 0.11 | 325 (75.1%) | 1 (27.3%) |
| sing-box | tuic | 0.14 | 101 (74.2%) | FAIL |
| honk | ss2022 | 0.19 | 1851 (67.2%) | 2928 (88.0%) |
| dae | ss2022 | 0.21 | 2448 (55.6%) | 2382 (89.8%) |
| sing-box | ss2022 | 0.19 | 2475 (56.5%) | 2944 (87.9%) |
| honk | trojan | 0.06 | 1623 (72.0%) | 3159 (91.8%) |
| dae | trojan | 0.13 | 2864 (49.6%) | 2631 (92.3%) |
| sing-box | trojan | 0.09 | 3226 (42.7%) | 4092 (88.9%) |
| honk | anytls-sb | 0.69 | 1294 (78.5%) | 1266 (96.5%) |
| dae | anytls-sb | 0.15 | 1278 (78.8%) | 2610 (91.1%) |
| sing-box | anytls-sb | 0.67 | 1268 (79.1%) | 2760 (90.7%) |
| honk | anytls-go | 0.12 | 1484 (76.5%) | 1269 (96.5%) |
| dae | anytls-go | 0.21 | 1435 (76.9%) | 2259 (93.2%) |
| sing-box | anytls-go | 0.98 | 1375 (77.8%) | 2248 (93.1%) |

注:第一轮稳态测量时实验室配置**未启用** `udp_warm_node_count`(honk 的 UDP
预热;生产配置为 8)。补上 `udp_warm_node_count: 8` 后重测 honk 各行如下
(dae/sing-box 无此开关,行不变):

| 引擎 | 协议 | 单流 Mbps(丢包) | P8 聚合 Mbps(丢包) |
| --- | --- | --- | --- |
| honk(开 udp_warm) | hy2 | 1622 (74.1%) | 1650 (95.5%) |
| honk(开 udp_warm) | tuic | **1252 (72.3%)** | FAIL |
| honk(开 udp_warm) | ss2022 | 1796 (68.7%) | 2916 (88.0%) |
| honk(开 udp_warm) | trojan | 1562 (73.2%) | 3283 (91.3%) |
| honk(开 udp_warm) | anytls-sb | 1254 (79.9%) | 1297 (96.2%) |
| honk(开 udp_warm) | anytls-go | 1400 (77.4%) | 1298 (96.3%) |

tuic 单流从 359 提升到 1252 Mbps——冷会话建立确实占了未预热测量的主要部分;
其余行在噪声范围内。anytls P8 垫底与 tuic P8 FAIL 与预热无关,为真实短板。

**稳态 UDP 解读(08-02):**

- **hy2**:honk 1663 ≈ sing-box 1607 > dae 938;P8 三家均不扩展(0.9–1.6 Gbps,
  丢包 96%+),与 08-01 稳态轮 honk hy2 单流 5.91 Gbps 相差甚远——见下方实验
  室条件备注。
- **tuic UDP 三引擎全部崩塌**(101–359 Mbps):同轮 direct UDP 基线(5300 端口,
  不过代理)实测也只有 1954 Mbps / 61% 丢包,说明本轮 .70→.59 的 UDP 链路本身
  已接近饱和上限。tuic 的绝对值不可与 08-01 稳态轮(6.18 Gbps)直接比较;
  该现象为实验室条件所致,待链路空闲后重测。
- **ss2022**:单流 sing-box 2475 ≈ dae 2448 > honk 1851;P8 honk 2928 ≈
  sing-box 2944 > dae 2382。honk 单流仍落后,P8 已追平。
- **trojan**:单流 sing-box 3226 > dae 2864 > honk 1623;P8 sing-box 4092 >
  honk 3159 > dae 2631。honk 的 trojan UDP-over-TCP 单流仍是三方最低,为
  头号 UDP 优化目标。
- **anytls UoT**:单流三方持平(~1.3–1.5 Gbps);**P8 honk 明显最低**
  (1266/1269 vs dae 2610/2259 vs sing-box 2760/2248)——anytls 多流 UDP 是
  新暴露的短板,值得专项分析。

### 08-02 结果解读

- **延迟**:honk 全面最优——cold 5–11ms(dae tuic 仍为每连接完整 QUIC 握手
  86ms;sing-box 8–13ms),hot p50 2.3–4.7ms。
- **TCP 带宽**:线速行(ss2022、trojan、anytls-go)三方基本持平
  (~8.7–9.4 Gbps)。QUIC 协议 honk 领先:hy2 2858(+3.7% vs dae、+11% vs
  sing-box),tuic 4134(+41% / +58%)。与 08-01 轮相比,dae 的 hy2/tuic
  带宽从 4467/4537 回落到 2757/2940,honk 的 hy2 恢复至同档。
- **UDP**:QUIC 协议 honk 大幅领先——hy2 1743(vs 931/1561),tuic 1577
  (vs 108/27,dae 与 sing-box 的 tuic UDP 本轮接近不可用)。**短板仍在
  UDP-over-TCP**:ss2022 1207 vs 2367/2509,trojan 1629 vs 2903/3330——
  honk 约为对手一半,仍是 UDP 方向头号优化目标。anytls-sb/go 三方持平
  (~1.3–1.5 Gbps)。
- **CPU**:honk 多数行最低(ss2022 0.39 vs 0.51/1.30 核;hy2 0.49 vs
  0.82/0.87;tuic 0.59 vs 0.82/0.89)。
- **RSS**:三方持平(47–62 MB)。

## 结果(2026-08-01,三引擎:honk vs dae vs sing-box)

honk: dev `ed640c7` (musl, mimalloc, reuseport-2 合入,单 UDP listener/协议族)。
dae: kdae 分支, Go 1.26.0。
sing-box: v1.13.14 (lab netns 内 TUN 客户端,按端口路由协议)。
三者同时间在实验室测试。延迟单位秒,TCP 带宽为 iperf3 接收端中位数,
CPU 单位核,RSS 为跑后值。sing-box 未测 CPU(TUN 客户端模式下无法分离
单协议进程 CPU)。

### TCP

| 引擎 | 协议 | cold | hot p50 | hot p95 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0060 | – | – | 9411 | 0.24 | 58 |
| dae | direct | 0.0035 | – | – | 9395 | – | 50 |
| sing-box | direct | 0.0085 | – | – | – | – | 59 |
| honk | hy2 | 0.0085 | 0.0042 | 0.0053 | 3050 | 0.50 | 60 |
| dae | hy2 | 0.0102 | 0.0023 | 0.0045 | 4467 | 1.07 | 66 |
| sing-box | hy2 | 0.0451 | 0.0046 | 0.0059 | 2998 | – | – |
| honk | tuic | 0.0051 | 0.0032 | 0.0051 | 4400 | 0.60 | 57 |
| dae | tuic | 0.0851 | 0.0037 | 0.0046 | 4537 | 0.98 | 64 |
| sing-box | tuic | 0.0151 | 0.0035 | 0.0041 | 2620 | – | – |
| honk | ss2022 | 0.0046 | 0.0028 | 0.0035 | 9205 | 0.36 | 52 |
| dae | ss2022 | 0.0076 | 0.0047 | 0.0058 | 9405 | 0.45 | 55 |
| sing-box | ss2022 | 0.0220 | 0.0027 | 0.0040 | 8717 | – | – |
| honk | trojan | 0.0103 | 0.0018 | 0.0084 | 9328 | 0.43 | 52 |
| dae | trojan | 0.0076 | 0.0018 | 0.0020 | 9369 | 0.66 | 57 |
| sing-box | trojan | 0.0150 | 0.0053 | 0.0064 | 9214 | – | – |
| honk | anytls-sb | 0.0053 | 0.0034 | 0.0046 | 4792 | 0.28 | 45 |
| dae | anytls-sb | 0.0139 | 0.0039 | 0.0047 | 5586 | 0.43 | 57 |
| sing-box | anytls-sb | 0.0083 | 0.0018 | 0.0023 | 8244 | – | – |
| honk | anytls-go | 0.0132 | 0.0031 | 0.0037 | 9249 | 0.48 | 56 |
| dae | anytls-go | 0.0232 | 0.0023 | 0.0027 | 9006 | – | – |
| sing-box | anytls-go | 0.0065 | 0.0019 | 0.0021 | 8823 | – | – |

### UDP (iperf3 `-u -b 10G -l 1200 -R`,单流,冷引擎)

| 引擎 | 协议 | echo RTT p50 | bw Mbps (丢包) | cpu |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.19 ms | 286 (95.3%) | 2.27 |
| dae | hy2 | 0.21 ms | 907 (85.9%) | 0.93 |
| sing-box | hy2 | 0.26 ms | 1629 (73.8%) | – |
| honk | tuic | 0.40 ms | 11 (99.2%) | 0.01 |
| dae | tuic | 0.27 ms | 1702 (67.4%) | 1.48 |
| sing-box | tuic | 0.15 ms | 100 (96.4%) | – |
| honk | ss2022 | 0.17 ms | 2010 (65.1%) | 1.31 |
| dae | ss2022 | 0.30 ms | 2742 (51.6%) | 1.79 |
| sing-box | ss2022 | 0.15 ms | 1984 (54.7%) | – |
| honk | trojan | 0.13 ms | 1659 (70.7%) | 1.28 |
| dae | trojan | 0.10 ms | 3062 (47.2%) | 1.70 |
| sing-box | trojan | 0.10 ms | 3557 (41.2%) | – |
| honk | anytls-sb | 0.28 ms | 1316 (79.0%) | 0.84 |
| dae | anytls-sb | – | – | – |
| sing-box | anytls-sb | 0.21 ms | 608 (78.8%) | – |
| honk | anytls-go | 0.19 ms | 1600 (74.5%) | 1.07 |
| dae | anytls-go | 0.12 ms | 1566 (74.3%) | – |
| sing-box | anytls-go | 0.10 ms | 640 (77.6%) | – |

### 三引擎对照解读

**TCP 带宽:**
- 线速协议(ss2022, trojan, anytls-go):三者均达 ~8.7–9.4 Gbps。honk 和
  dae 差距在噪声范围内;sing-box 略低(ss2022 8717 vs 9405,anytls-go
  8823 vs 9249)。
- QUIC 协议(hy2, tuic):dae 领先 4467/4537 Mbps。honk 3050/4400,sing-box
  2998/2620。honk 的 hy2 相对 07-30 轮(5239→3050)有回退,疑似实验室宿
  主机负载影响。
- anytls-sb: sing-box 8244 领先,dae 5586,honk 4792。这是 sing-box 参考
  实现;honk anytls handler 落后约 40%。

**CPU 效率:**
- 在可比较的 QUIC 行上,honk CPU 约为 dae 的 50%(hy2:0.50 vs 1.07,
  tuic:0.60 vs 0.98)。
- TCP 类协议 honk 也持续比 dae 低 0.3–0.5 核。

**延迟:**
- dae tuic 冷延迟仍为每次连接完整 QUIC 握手(85ms vs honk ticket-cache
  恢复 5ms)。
- sing-box 冷延迟全面最高(TUN + 用户态路由增加 ~10–35ms)。
- 热延迟三者均在个位数 ms。

**UDP(冷引擎,单流):**
- 本轮在冷引擎上测量(健康检查未收敛),UDP 数值比稳态低 3–5 倍。稳态
  数据见下方"稳态三引擎对比"。
- TUIC UDP 三引擎冷启动全挂(11–100 Mbps),但预热后 honk 单流达 6.18
  Gbps——冷启动是会话建立的假象,不是协议限制。

### UDP:稳态三引擎对比

三个引擎分别启动,等待 30s 健康检查收敛,随后通过各协议进行 TCP 预热,
再等 10s 稳定后测量。单流和 8 流聚合(`iperf3 -u -b 10G -l 1200 -R` /
`-P 8`)。报文固定 1200B。

| 引擎 | 协议 | echo RTT | 单流(丢包) | P8 聚合(丢包) |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.12 ms | 5.91 Gbps (5.9%) | P8 失败† |
| dae | hy2 | 0.59 ms | 915 Mbps (85.8%) | 827 Mbps (97.6%) |
| sing-box | hy2 | 0.42 ms | 1.61 Gbps (74.4%) | 1.58 Gbps (95.9%) |
| honk | tuic | 0.32 ms | **6.18 Gbps (2.1%)** | **9.40 Gbps (0.8%)** |
| dae | tuic | 0.15 ms | 1.57 Gbps (71.4%) | 21 Mbps (45.3%) |
| sing-box | tuic | 0.14 ms | 31 Mbps (80.1%) | 失败 |
| honk | ss2022 | 0.23 ms | 5.67 Gbps (11.5%) | 8.83 Gbps (6.8%) |
| dae | ss2022 | 0.21 ms | 2.52 Gbps (55.1%) | 2.59 Gbps (88.8%) |
| sing-box | ss2022 | 0.17 ms | 2.57 Gbps (55.1%) | 3.00 Gbps (87.3%) |
| honk | trojan | 0.07 ms | **6.31 Gbps (0.06%)** | 8.74 Gbps (7.8%) |
| dae | trojan | 0.13 ms | 2.96 Gbps (49.6%) | 2.87 Gbps (91.8%) |
| sing-box | trojan | 0.09 ms | 3.52 Gbps (39.1%) | 4.31 Gbps (88.6%) |
| honk | anytls-sb | 0.06 ms | 5.54 Gbps (13.6%) | **9.24 Gbps (2.5%)** |
| dae | anytls-sb | 0.25 ms | 1.31 Gbps (78.8%) | 2.87 Gbps (89.9%) |
| sing-box | anytls-sb | 1.78 ms | 1.26 Gbps (79.2%) | 2.85 Gbps (90.9%) |
| honk | anytls-go | 0.08 ms | **6.44 Gbps (0.4%)** | **9.37 Gbps (1.1%)** |
| dae | anytls-go | 0.13 ms | 1.58 Gbps (74.2%) | 2.45 Gbps (92.6%) |
| sing-box | anytls-go | 0.10 ms | 1.45 Gbps (76.3%) | 2.36 Gbps (92.9%) |

† honk hy2 P8 本轮失败(iperf3 返回 0);此前稳态曾录得 9.18 Gbps / 3.1%
丢包。空闲实验室重测可确认。

### 稳态 UDP 解读

**Honk 在稳态 UDP 上全面领先:**
- 单流:5.5–6.4 Gbps,丢包 0.06–13.6%。dae 和 sing-box 仅 0.9–3.5 Gbps,
  丢包 40–86%——honk **快 2–6 倍,丢包低 5–15 倍**。
- P8 聚合:honk 达 8.7–9.4 Gbps(接近线速),丢包 0.8–7.8%。dae 和
  sing-box P8 崩溃,丢包 88–98%——它们的 UDP 数据面无法承载 8 条并行饱
  和流。
- **TUIC UDP** 从冷启动 11 Mbps 跃升至 **6.18 Gbps**(560 倍提升)。协议
  本身没问题;冷启动数据是会话建立的假象,不是协议限制。
- **Trojan UDP** 6.31 Gbps / 0.06% 丢包——honk 的 UDP-over-TCP 组帧在线
  速下无可测开销。
- **anytls-go** 6.44 Gbps / 0.4% 单流,9.37 Gbps / 1.1% P8,综合最强。

**dae 和 sing-box P8 崩溃不是实验室假象:**
两者表现一致——单流 1–3.5 Gbps 丢包尚可,P8 吞吐量不升反降,丢包飙至
88–98%。这说明它们的 UDP 接收路径存在根本瓶颈(共享 socket buffer 竞
争、缺少逐流排队或内核级 UDP socket 锁竞争),而这正是 honk 的
`UdpEndpointPool` 和逐流有界队列专门设计要解决的问题。

## 结果(2026-07-31,honk dev `ac64fe1` vs dae kdae `eee7c88b`)

实验室同时刻 A/B。honk 为 musl release 构建(mimalloc,周期性
`mi_collect` 已移至 blocking 线程并延迟首个周期,drain 改为空闲超时);
dae 为 kdae 分支 `eee7c88b`(新增 DNS group override 修复,outbound
fork 升至 `perf/complete-optimizations@670df833`)。延迟单位秒,带宽为
iperf3 接收端中位数,CPU 单位核,RSS 为跑后值。本轮新情况:**kdae 的
direct 基线已修复**(07-30 轮是坏的)。

| 引擎 | 协议 | cold | hot p50 | hot p95 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0052 | – | – | 9406 | 0.24 | 52 |
| honk | hy2 | 0.0101 | 0.0032 | 0.0046 | 2921 | 0.48 | 59 |
| honk | tuic | 0.0093 | 0.0034 | 0.0043 | 3961 | 0.55 | 59 |
| honk | ss2022 | 0.0044 | 0.0027 | 0.0040 | 9392 | 0.36 | 52 |
| honk | trojan | 0.0072 | 0.0019 | 0.0120 | 9341 | 0.45 | 53 |
| honk | anytls-sb | 0.0050 | 0.0031 | 0.0039 | 4790 | 0.30 | 57 |
| honk | anytls-go | 0.0122 | 0.0032 | 0.0040 | 9226 | 0.49 | 56 |
| dae | direct | 0.0051 | – | – | 9397 | 0.00 | 52 |
| dae | hy2 | 0.0090 | 0.0032 | 0.0037 | 3005 | 0.82 | 63 |
| dae | tuic | 0.0827 | 0.0792 | 0.0800 | 4280 | 0.93 | 64 |
| dae | ss2022 | 0.0040 | 0.0036 | 0.0062 | 9404 | 0.42 | 57 |
| dae | trojan | 0.0105 | 0.0078 | 0.0100 | 9340 | 0.65 | 57 |
| dae | anytls-sb | 0.0112 | 0.0029 | 0.0038 | 4742 | 0.37 | 58 |
| dae | anytls-go | 0.0069 | 0.0034 | 0.0046 | 9301 | 0.63 | 60 |

UDP(iperf3 `-u -b 10G -l 1200 -R`,接收端 Mbps + 丢包):

| 引擎 | 协议 | echo RTT p50 | bw Mbps (丢包) | cpu |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.43 ms | 1708 (72.9%) | 1.07 |
| honk | tuic | 0.31 ms | 142 (64.5%) | 0.13 |
| honk | ss2022 | 0.22 ms | 1879 (66.6%) | 1.28 |
| honk | trojan | 0.18 ms | 1609 (71.9%) | 1.27 |
| honk | anytls-sb | 0.49 ms | 1308 (78.2%) | 0.86 |
| honk | anytls-go | 0.18 ms | 1607 (74.2%) | 1.04 |
| dae | hy2 | 0.27 ms | 929 (85.9%) | 0.95 |
| dae | tuic | 0.28 ms | 60 (52.4%) | 0.06 |
| dae | ss2022 | 0.16 ms | 2705 (52.4%) | 1.74 |
| dae | trojan | 0.11 ms | 2972 (48.7%) | 1.69 |
| dae | anytls-sb | 0.13 ms | 1305 (78.8%) | 0.85 |
| dae | anytls-go | 0.10 ms | 1413 (76.0%) | 0.92 |

### 07-31 结果解读

- **TCP 带宽**基本持平:线速行(direct、ss2022、trojan、anytls-go)
  两边都在 ~9.3–9.4 Gbps;anytls-sb 也首次打平(4790 vs 4742——新
  kdae 在这一行不再领先)。hy2/tuic 略偏 dae(3005/4280 vs 2921/3961)。
- **每 Gbps CPU** 依然是 honk 的强项,全部 QUIC 行:hy2 0.48 vs
  0.82 核,tuic 0.55 vs 0.93,trojan 同带宽下 0.45 vs 0.65。
- **延迟**:dae 的 tuic 仍为每条连接付完整 QUIC 握手(cold 82.7ms、
  hot p50 79.2ms;honk 靠票据缓存恢复,9.3/3.4ms)。其余行都在个位
  数毫秒。
- **UDP**:honk 领先 hy2(1708 vs 929)与 anytls-go;ss2022/trojan 的
  UDP-over-TCP 差距仍在(dae 2705/2972 vs honk 1879/1609),仍是 UDP
  方向的头号优化目标。tuic UDP 两边都差(142/60 Mbps)。
- honk 的 hy2/tuic TCP 带宽较 07-30 轮下降明显(5239→2921、
  5351→3961)而 dae 基本持平;本轮跑测时 .70 实验宿主机有高并发负
  载,这两行标记为存疑,待实验室空闲时复测确认。

## 结果(2026-07-30,honk dev session 各阶段完成后 vs dae kdae,AES-NI)

实验室同时刻 A/B(引擎 VM 已换 host 透传 CPU;更早的软件加密时代见
"已知的实验室限制")。延迟单位为秒(curl `time_total`),带宽为
iperf3 接收端中位数,CPU 为核数,RSS 为跑完后值。honk 为 musl 发布
二进制(mimalloc)。

| 引擎 | 协议 | cold | hot p50 | hot p95 | 带宽 (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0052 | – | – | 9413 | 0.16 | 53 |
| honk | hy2 | 0.0058 | 0.0018 | 0.0032 | 5239 | 1.06 | 64 |
| honk | tuic | 0.0024 | 0.0038 | 0.0049 | 5351 | 1.06 | 66 |
| honk | ss2022 | 0.0038 | 0.0018 | 0.0025 | 9388 | 0.37 | 57 |
| honk | trojan | 0.0053 | 0.0014 | 0.0055 | 9366 | 0.42 | 49 |
| honk | anytls-sb | 0.0052 | 0.0020 | 0.0031 | 4954¹ | – | 58 |
| honk | anytls-go | 0.0126 | 0.0035 | 0.0046 | 9272¹ | – | 55 |
| dae | direct | 故障² | – | – | – | – | – |
| dae | hy2 | 0.0109 | 0.0030 | 0.0043 | 2996 | 0.75 | 62 |
| dae | tuic | 0.0852 | 0.0797 | 0.0809 | 3920 | 0.84 | 64 |
| dae | ss2022 | 0.0063 | 0.0040 | 0.0042 | 9396 | 0.49 | 52 |
| dae | trojan | 0.0093 | 0.0084 | 0.0107 | 9370 | 0.66 | 57 |
| dae | anytls-sb | 0.0088 | 0.0014 | 0.0023 | 9155 | 0.60 | 58 |
| dae | anytls-go | 0.0044 | 0.0017 | 0.0021 | 9379 | 0.62 | 59 |
| sing-box | direct | 0.0044 | – | – | 9410 | 0.41 | 47 |
| sing-box | hy2 | 0.0143 | 0.0014 | 0.0018 | 2930 | 0.88 | 52 |
| sing-box | tuic | 0.0102 | 0.0029 | 0.0048 | 2808 | 0.86 | 50 |
| sing-box | ss2022 | 0.0042 | 0.0040 | 0.0056 | 9390 | 1.19 | 49 |
| sing-box | trojan | 0.0112 | 0.0068 | 0.0104 | 9368 | 0.78 | 47 |
| sing-box | anytls-sb | 0.0113 | 0.0035 | 0.0041 | 5996 | 0.59 | 49 |
| sing-box | anytls-go | 0.0129 | 0.0023 | 0.0028 | 9252 | 0.95 | 46 |

dae 各行为 **kdae 分支构建**(`2a007b39`,`unstable-20260729.r987`,
在压测机上从 `../dae` 构建)——第一个支持 AnyTLS 的 dae 构建。
sing-box 各行为 **1.13.14**,以 TUN 客户端身份跑在 lab netns **内部**
(`bench/sb-client.json` 部署到引擎机;按端口的路由规则与引擎配置一致,
outbound 绑定 `veth-client`)。

¹ honk 的 anytls 两行有一段历史:单流 iperf3 曾只有 2–3 Mbps。根因在
honk 自身——单流 demux 队列满(64 帧)会**立即**杀流,单流测试中服务器
的初始飞行快过新建 relay 任务,22ms 就触发杀流;随后服务器继续向池化
会话灌死 sid 的 PSH 垃圾帧。上表实测使用第一版有界 HOL 修复,即最多
等待 5s 再杀。当前路径不等待:按流分桶并设置 512 帧、每流 2 MiB、每会话
8 MiB 的硬上限;触及上限时,已接纳数据排空后立即只 reset 肇事流。
历史实测中 anytls-go 与 dae 持平;anytls-sb 落后(sing-box 服务端的帧模式
dae 容忍得更好——后续工作)。

² dae 的 direct 路径在本实验室内核上故障(kdae 构建):direct 流超时,
代理流正常。上表 dae 各协议行有效;无 dae direct 基线。

### UDP 结果(iperf3 `-u -b 10G -l 1200 -R` + echo RTT)

同一轮 A/B。供给速率固定 10 Gbps——远超任何隧道的承载,所以丢包列
反映的是饱和而不是质量;接收端带宽才是容量数字。数据报长度固定
1200B:QUIC datagram 上限就在那附近(honk hy2/tuic 会丢超限数据报
——iperf3 按路径 MTU 的默认 ~1448B 测到的是上限而不是隧道)。
echo RTT 为每协议路由 echo 端口(53531–53536)15 次 ping 的中位数。

| 引擎 | 协议 | echo RTT p50 | 带宽 Mbps(丢包) | cpu |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.37 ms | 1738 (73.1%) | 1.30 |
| honk | tuic | 0.38 ms | 293 (54.3%) | 0.22 |
| honk | ss2022 | 0.11 ms | 1158 (52.4%) | 0.81 |
| honk | trojan | 0.21 ms | 1506 (77.3%) | 1.26 |
| honk | anytls-sb | 0.12 ms | 1148 (82.2%) | 0.80 |
| honk | anytls-go | 0.10 ms | 1519 (76.6%) | 1.11 |
| dae | hy2 | 0.14 ms | 932 (85.9%) | 0.96 |
| dae | tuic | 0.13 ms | 9 (75.8%) | 0.03 |
| dae | ss2022 | 0.10 ms | 2668 (53.1%) | 1.76 |
| dae | trojan | 0.13 ms | 2957 (49.2%) | 1.67 |
| dae | anytls-sb | 0.10 ms | 1208 (80.7%) | 0.78 |
| dae | anytls-go | 0.19 ms | 1561 (75.2%) | 0.99 |
| sing-box | hy2 | 0.20 ms | 1372 (75.2%) | 1.18 |
| sing-box | tuic | 0.15 ms | 16 (63.4%) | 0.04 |
| sing-box | ss2022 | 0.07 ms | 2730 (53.0%) | 1.35 |
| sing-box | trojan | 0.07 ms | 3380 (45.5%) | 1.56 |
| sing-box | anytls-sb | 0.09 ms | 1244 (79.3%) | 1.12 |
| sing-box | anytls-go | 0.13 ms | 1447 (76.9%) | 1.21 |

- **hy2 UDP**:honk 领先(1738 vs 932 / 1372),三家都约 1 核。
- **TUIC UDP** 三家都弱(293 / 9 / 16 Mbps)——QUIC-datagram TUIC 在
  本实验室是协议级短板,honk 是其中最好的。
- **UDP-over-TCP 隧道**(ss2022、trojan):dae/sing-box 领先
  (2.7–3.4 Gbps vs honk 1.1–1.5)。honk 的 UDP endpoint/分帧路径是
  当前瓶颈——anytls-sb 之后的下一个优化目标。
- **anytls UoT**:三方持平,约 1.1–1.5 Gbps。
- echo RTT 全部亚毫秒,没有协议是延迟受限的。

### 结果解读

- **带宽**:honk 全面领先或打平。hy2 5239(+75% vs dae、+79% vs
  sing-box)、tuic 5351(+36% / +90%)、trojan 和 ss2022 与两家同为
  线速、anytls-go 9272(三方持平)。唯一剩余的差距是对 sing-box
  服务端的 anytls:honk 4954 vs dae 9155 / sing-box 5996。ss2022 靠
  BoringSSL AEAD 替换达成线速:RustCrypto aes-gcm 实测 0.4–0.5 GB/s
  (AES-NI 路径未启用)vs BoringSSL 3.3–6.7 GB/s(`benches/ss_aead.rs`),
  替换把该行从 5339 Mbps / 1.01 核提到 9388 / 0.37 核——CPU 也反超
  dae(0.37 vs 0.49)。
- **每核带宽**:honk 在每一行线速协议上效率最高——trojan 0.42 核
  (dae 0.66、sing-box 0.78),ss2022 0.37 核(dae 0.49、sing-box
  1.19)。QUIC 协议 honk 用 ~1.06 核跑 5.2+ Gbps;dae/sing-box 要
  0.75–0.88 核跑 2.8–3.9 Gbps。
- **延迟**:TUIC 仍是极端案例——热开流 3.8 ms vs dae 79.7 ms(honk 有
  进程级 TLS 1.3 票据缓存,dae 每条连接完整 QUIC 握手;冷启动同样,
  2.4 vs 85.2 ms)。其他行在几 ms 内互有胜负。
- **内存**:honk 的 musl 构建用 mimalloc,它会保留回收的内存
  arena——RSS 49–66 MB,与 dae(52–64 MB)持平。这是刻意的交换:
  mimalloc 比 musl 原生 malloc 带来约 +50% 的 QUIC 吞吐(A/B:5096 vs
  3037 Mbps),代价是约 40 MB 驻留内存。

### 更早的结果(软件加密实验室,AES-NI 之前)

引擎 VM 换 host 透传 CPU 之前,QUIC 数字对两个引擎都受限于软件加密:
honk hy2/tuic 2289/2383 Mbps vs dae(kdae)2511/2669,honk 的 BoringSSL
卡在 `nohw` C 版 ChaCha20(占引擎 CPU 34%)。那些行已被上表取代。
QUIC socket 缓冲修复(8 MiB SO_RCVBUF/SO_SNDBUF + rmem_max/wmem_max
提到 16 MiB)和 8/32 MiB 接收窗口默认值先于两张表,对两者都适用。

## DNS 微基准(criterion)

`cargo bench -p honk-core --bench dns`——纯 loopback,不需要外部网络。
最近一次结果(2026-07-30,x86_64):

| 基准 | 均值 |
| --- | --- |
| endpoint 解析(udp/dot/doh/doq/h3) | 70–97 ns |
| 缓存 get(命中) | 60 ns |
| 缓存 put | 133 ns |
| 缓存 90% 读 / 10% 写混合 | 32 ns |
| 路由匹配(每查询规则求值) | 29–79 ns |
| force/restore txid | 1.4 ns |
| 构造 A 查询 | 114 ns |
| forwarder resolve(缓存命中) | 283 ns |
| TCP 池 exchange(连接复用) | 18 µs |
| UDP 上游 exchange | 19 µs |
| 长度前缀 framing(duplex) | 6 µs |

单查询总成本(路由 + 缓存命中)远低于 1 µs;上游 exchange 符合 loopback RTT
量级。基准代码在 `crates/honk-core/benches/dns.rs`;mock server 必须开
nodelay——否则 Nagle + delayed-ACK 会给每次 TCP exchange 加约 40 ms,
测出来的是操作系统而不是代码。

`cargo bench -p honk-outbound --bench ss_aead` 对比 AEAD 后端在 SS 分块
尺寸下的吞吐(RustCrypto aes-gcm 0.4–0.5 GB/s vs BoringSSL AeadCtx
3.3–6.7 GB/s,AES-NI 硬件——SS 数据面用 BoringSSL 的原因)。

## Candidate UDP 微基准（绝对值，不是 A/B）

UDP Criterion suite 只记录 candidate 的绝对行为。固定调用为：

```bash
cd /root/code/honk-feat-udp-to-1
CARGO_TARGET_DIR=/root/code/honk/target cargo bench -p honk-core --bench udp -- --save-baseline udp-candidate
```

| Case | 固定工作量 |
| --- | --- |
| steady enqueue | 一个 Ready flow 上 1,000,000 次 128-byte `fast_path_enqueue`，每次立即 drain 以保持 steady state |
| reserve / rollback | 10,000 次 endpoint reservation 后 rollback |
| histogram | 1,000,000 次 record/snapshot operation |
| queue saturation | 先接纳 64 个 datagram，再丢弃一个最新 datagram |

记录 candidate 的 Criterion mean、median、MAD 与绝对吞吐。`udp-candidate`
只是重复运行标签，不是与 `be587b1` 的比较：该 revision 没有可用于有效 A/B
的 source-level 等价接口。Criterion 也不提供 merge gate 的 p95 estimate；不得
从该 suite 推断 p95。

## Deployment UDP A/B gate

`bench/udp-latency.sh` 是真实部署驱动，而非 CI 替代品。它要求两个 binary 使用
相同的 TPROXY topology 与真实 upstream。固定调用为：

```bash
sudo bench/udp-latency.sh \
  --baseline-bin /opt/honk/be587b1/honk-core \
  --candidate-bin /opt/honk/udp-to-1/honk-core \
  --config /etc/honk/bench.dae \
  --echo-target 10.0.2.2:9000 \
  --dns-target 10.0.2.2:53 \
  --samples 10000 --runs 5 --offered-rate 5000
```

该固定调用刻意不传 timeout 或 hook flag。请在 root 环境配置
`HONK_UDP_TIMEOUT_SEC`（默认 `30`）以及
`HONK_UDP_{START,READY,SETUP,PROBE,STATS,TEARDOWN,TOPOLOGY}_HOOK`；CLI flag
可覆盖这些值。使用 `sudo` 时，须以 `--preserve-env` 保留这些变量，或在 root
环境中配置它们。driver 不提供 built-in topology；缺少 live hook 会 fail closed。

每个 executable hook 都通过 `env` 运行，不会把 shell snippet `eval`。它会获得
`variant`、`case`、`run`、`workdir`、`pid`、`pgid`、`selected_bin`、
`baseline_bin`、`candidate_bin`、`config`、`echo_target`、`dns_target`、
`samples`、`offered_rate` 与 `timeout`；`start` 和 `topology` 的 `pid`/`pgid`
为空。`start` 必须先完成同步 setup，再执行 `exec "$selected_bin" ...`；driver
会把所选文件的 device/inode 与 `/proc/$pid/exe` 核对，并在 ready、setup、probe、
stats 后重新验证同一 PID/session/start-time/executable。只有 teardown 完成且在
bounded wait 内确认所属 process group 已消失后才输出 row；残留 descendant 会
fail closed。旧 positional arguments 仍兼容。target 可为 IPv4、`[IPv6]` 或
带端口的合法 hostname。`probe` 必须报告 `sent == samples`。

它为每个 case/run 输出一个 JSONL object，顶层字段严格为：`schema_version`、
`variant`、`commit`、`binary_sha256`、`kernel`、`topology`、`case`、`run`、
`samples`、`offered_rate`、`sent`、`received`、`latency_unit`、`p50`、`p95`、
`p99`、`max`、`loss`、`cpu_pct`、`rss_kib`、`fd_count`、`queue_drops` 与
`warm_hit`。`schema_version` 为 `1`；延迟 quantile 的单位为 microseconds；
`loss` 为 sample loss ratio，`cpu_pct` 为进程 CPU usage，`rss_kib` 为 KiB 的
resident memory，`fd_count` 为打开的 file-descriptor count。固定 case 为
`cold_endpoint`、`steady_hit`、`warm_session_cold_endpoint`、`dns_hit`、
`dns_miss`、`healthy_candidate` 与 `blackholed_candidate`。driver interface 与
JSONL shape 由 `bash bench/tests/udp-latency-cli.sh` 检查。

部署 gate 在相同 topology 与 offered rate 下比较五轮各 10,000 sample：healthy
cold 的 p50/p95 回退最多 5%；首个 candidate 被 blackhole 时 p95 至少改善 20%、
p99 至少改善 30%；steady path 在目标吞吐 70% 以下须保持 p99 至多 250 microseconds
且零 drop；AnyTLS warm hit 须达 80%，且 first reply 减少一个 RTT 或至少 20%；
steady CPU 与 p50 回退最多 5%；IPv4/IPv6 client-observed reply tuple 必须不变。
**本地 worktree 未运行 deployment gate，因此不声称达到任何网络延迟 gate。**

## Release profile 与 allocator 矩阵

`bench/release-matrix.sh` 对比显式的 `release-size`、
`release-size-thin`、`release-speed` 与 `release-speed-thin` profile，并配对
三种 allocator arm：关闭 collect 的 mimalloc、60 秒 collect 的 mimalloc，以及
系统 allocator。每个 cell 使用隔离的 Cargo、workload cache 与 run 目录，并输出
machine metadata、JSONL/CSV build 和 performance 记录。

不编译即可验证全部四种受支持 target 配置：

```bash
bench/release-matrix.sh --all-targets --dry-run --output /tmp/honk-release-matrix
```

主机实测需要提供可执行的 `--benchmark-hook`；其 RSS/PSS/fault/CPU/throughput/
latency 字段契约可由 `bench/release-matrix.sh --help` 查看。完整矩阵期间必须把
所有 CPU policy 固定到同一 governor，并保持 turbo 状态不变；`machine.json` 会记录两项
设置。只能在同一机器和 workload 下比较 cell。该矩阵记录证据；没有部署吞吐
与尾延迟结果时，不据此切换发布 profile。

profile 晋级采用显式门禁，不能只看二进制尺寸。以 `release-size` 为基线，同一
实验室的五轮配对结果中，candidate 的每项吞吐回退不得超过 3%、每项 p99
延迟回退不得超过 5%、RSS 增幅不得超过 20%。三个门禁全部通过前，发布默认
保持尺寸版。

2026-08-02 完成了一轮初步配对部署：x86_64 musl、mimalloc、60 秒 collect，
对比 `release-size` 与 `release-speed`。每个协议执行三轮 8 秒反向吞吐；
warm-up 后另测 200 次请求的尾延迟。

| profile | 二进制 | direct | hy2 | tuic | 最大 RSS | hy2 p99 | tuic p99 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| release-size | 19.50 MB | 9.407 Gbps | 2.756 Gbps | 4.253 Gbps | 56 MB | 5.426 ms | 4.705 ms |
| release-speed | 24.79 MB | 9.388 Gbps | 3.314 Gbps | 5.152 Gbps | 59 MB | 3.409 ms | 3.136 ms |

速度版没有吞吐或 p99 回退，最大 RSS 增加 5.4%，因此这一个样本通过数值门禁。
但单轮配对尚未满足五轮证据要求，且二进制增大 27.2%，所以不执行晋级，
`release-size` 继续作为默认。

## 生产备注(10.10.10.1 网关)

- 每次部署后 TCP(google/baidu/cloudflare)与 HTTP/3(cloudflare)通过;
  网关日志干净。
- HTTP/3 停顿突发(首字节快、正文停约 14s)以分钟级波动出现,与订阅 UDP
  线路质量相关而非引擎构建——相邻构建的 A/B 部署在同一小时内两种结果都
  出现过。客户端 qlog 显示约 12% 的 datagram 被先判丢后到(延迟假象,非
  内核/socket 丢包)。
- 每次部署后跑 60 分钟 canary,采样 FD / established / CLOSE-WAIT /
  warn 速率;Ready 池指标(`/stats` → `pool`:hits、misses、entries)
  以同样节奏检查。

## 回归门禁

- `just outbound-ci`——fmt、clippy、honk-config + honk-outbound 测试套件。
- `just clash-ci`——fmt、clippy、clash_api_test + integration_test。
- `just dns-ci`——DNS 子系统门禁。
- `cargo bench -p honk-core --bench dns`——DNS 微基准(见上)。
- `cargo bench -p honk-core --bench udp -- --save-baseline udp-candidate`——仅 candidate 的绝对 UDP 测量；不是历史 A/B 或 p95 merge gate。
- `bash bench/tests/udp-latency-cli.sh`——deployment driver 的 CLI/JSONL fixture；上文真实 UDP A/B gate 仍需要 TPROXY 与 upstream。
- `bash bench/tests/runtime-memory-cli.sh`——配对 runtime-memory driver 的 CLI、顺序、identity 与 fail-closed JSONL fixture。
- 发布 CI(`.github/workflows/release.yml`)——workspace 测试门禁 +
  四目标构建(x86_64/aarch64 × gnu/musl)+ BTF 检查 + tarballs。
