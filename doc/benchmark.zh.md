# Benchmark 实验环境与结果

本文档描述 honk 可复现的 benchmark 环境、测量方法学,以及与
[dae](https://github.com/daeuniverse/dae) 的同时刻 A/B 最新结果。文档放在仓库里,
以便实验方法和数据与代码保持同步。

## 实验拓扑

```text
┌─────────────────────────────┐         ┌─────────────────────────────┐
│ 10.10.10.50 (VM, 4C/2G)     │         │ 10.10.10.70 (物理机, 50G)   │
│                             │         │                             │
│  ┌───────────────┐          │  LAN    │  协议服务端:                │
│  │ netns "lab"   │ veth     ├────────►│   hy2        :8443/udp      │
│  │ 192.168.222.2 ├──────────┤         │   tuic       :2444/udp      │
│  └───────┬───────┘          │         │   anytls-sb  :2445/tcp      │
│          │ NAT + TPROXY     │         │   anytls-go  :2443/tcp      │
│  honk / dae(同一时刻只跑一个)│         │   ss-2022    :2447/tcp      │
│  lan_ifname: veth-lab       │         │   trojan     :2446/tcp      │
│  wan_ifname: ens3           │         │  目标服务:                  │
└─────────────────────────────┘         │   http       :8001-8006,8080│
                                        │   iperf3     :5201-5206,5300│
                                        │   udp echo   :53530         │
                                        └─────────────────────────────┘
```

- **引擎机(10.10.10.50)**:同一时刻只运行 honk 或 dae 之一。客户端在
  network namespace `lab` 里(veth 对 `veth-lab` ↔ `veth-client`,
  192.168.222.0/24,nftables masquerade NAT)。所有客户端流量都经过引擎真实的
  eBPF 数据面,因此数字包含完整内核路径,不是 loopback 捷径。
- **服务端(10.10.10.70)**:协议服务端(官方 hysteria、tuic-server、
  sing-box、Go anytls-server)加本地目标服务。服务端直接出 WAN,所以
  "internet" 测试会经过 服务端 → 外网。
- **隔离**:这里的一切不触碰生产网关(10.10.10.1)。生产验证单独进行,
  并会明确标注。

### 已知的实验室限制

- 两台 VM 都是单队列 virtio 网卡。VM↔VM 吞吐上限约 0.8–1.7 Gbps TX;
  物理机↔VM 可达 9.4 Gbps。因此带宽测试的服务端放在**物理机**上:客户端
  RX(9.4 Gbps)是天花板,而不是 VM 间链路。direct 基线(引擎 direct 路径 +
  NAT):**约 9.4 Gbps**。
- 共享基础设施上跑与跑之间方差 ±5%;WAN 订阅上的停顿类假象以分钟级窗口波动,
  不是引擎回退——见下文"生产备注"。
- 实验室是共享的。如果某一行数据看起来不对,发布前先重跑(别人中途重启引擎
  会污染测量)。

## 各组件位置

| 组件 | 二进制 | 配置 |
| --- | --- | --- |
| hy2 server | 官方 `hysteria` | `:8443`,密码 `testpass123`,证书 CN `hy2.test` |
| TUIC server | `tuic-server` 1.0.0 | `:2444`,uuid `00000000-0000-0000-0000-000000000001` / `testpass123`,要求 SNI `hy2.test` |
| AnyTLS server | sing-box | `:2445`,密码 `testpass123` |
| AnyTLS server | Go 参考实现 `anytls-server` | `:2443`,`-p testpass123` |
| SS 2022 server | sing-box | `:2447`,`2022-blake3-aes-128-gcm`,psk `8JCsHssyVTFyPy5lYdNhZg==` |
| Trojan server | sing-box | `:2446`,密码 `testpass123`,SNI `hy2.test` |
| 目标服务 | python http.server, iperf3 | 端口 `8001-8006` + `8080`(direct),`5201-5206` + `5300`(direct);UDP echo `:53530` |

引擎配置按目标端口路由,无需 API 切换:
`5201/8001 → hy2`、`5202/8002 → tuic`、`5203/8003 → ss2022`、
`5204/8004 → trojan`、`5205/8005 → anytls-sb`、`5206/8006 → anytls-go`
(仅 honk——dae 不支持 AnyTLS)。节点服务端端口为 `direct(must)`,
其余全部回落 direct。

## 方法学

统一 harness——`bench/lab-bench.sh`(在本仓库,于引擎机上运行)——
取代了旧的 bench.sh / bench-cold.sh / bench-cpu.sh / bench-honest.sh
四个脚本。用法和实验室要求见 `bench/README.md`。

每个 引擎 × 协议 测量:

- **cold**——全新重启引擎后的首个请求延迟,3 次取中位数。两个实验室配置的
  健康检查间隔都是 3600s,首个探测不会抢跑测量。
- **hot p50/p95**——对每协议 HTTP 目标连发 15 个请求的开流延迟(代理会话已
  热)。QUIC 协议这项主要由连接/会话恢复决定,mux 协议由池化会话决定。
- **bw**——iperf3 `-R` 下载,单流,3 次取接收端中位数。
- **cpu**——中位数带宽那一轮期间的引擎 CPU 核数
  (`/proc/<pid>/stat` utime+stime 差值除以墙钟时间)。honk 的 pid 锚定
  clash API 监听者,停在单实例锁上的第二实例(零 CPU)不会污染指标。
- **rss**——带宽轮结束后的引擎 RSS。
- **direct 基线**——同样方法测量未代理路径(`8080`/`5300`)。

```bash
scp bench/lab-bench.sh root@10.10.10.50:/root/
ssh root@10.10.10.50 "bash /root/lab-bench.sh 'honk dae' 'hy2 tuic ss2022 trojan anytls-sb anytls-go'"

# 协议正确性矩阵(每协议 TCP 目标 / UDP echo / 外网)
ssh root@10.10.10.50 bash /root/test-protocols.sh
```

## 结果(2026-07-30,honk dev session 各阶段完成后 vs dae)

实验室同时刻 A/B,方法如上。延迟单位为秒(curl `time_total`),带宽为
iperf3 接收端中位数,CPU 为核数,RSS 为跑完后值。

| 引擎 | 协议 | cold | hot p50 | hot p95 | 带宽 (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0051 | – | – | 9397 | 0.25 | 14 |
| honk | hy2 | 0.0082 | 0.0042 | 0.0055 | 2289² | 0.95 | 16 |
| honk | tuic | 0.0109 | 0.0033 | 0.0041 | 2383² | 1.04 | 15 |
| honk | ss2022 | 0.0043 | 0.0041 | 0.0049 | 1314 | 1.01 | 15 |
| honk | trojan | 0.0051 | 0.0025 | 0.0104 | 4427 | 1.03 | 14 |
| honk | anytls-sb | 0.0059 | 0.0021 | 0.0029 | 见注¹ | 0.00 | 14 |
| honk | anytls-go | 0.0086 | 0.0023 | 0.0026 | 见注¹ | 0.00 | 14 |
| dae | direct | 0.0087 | – | – | 9408 | 0.00 | 46 |
| dae | hy2 | 0.0095 | 0.0038 | 0.0047 | 2511 | 1.45 | 64 |
| dae | tuic | 0.0865 | 0.0792 | 0.0809 | 2669 | 1.44 | 64 |
| dae | ss2022 | 0.0066 | 0.0039 | 0.0052 | 1528 | 1.01 | 50 |
| dae | trojan | 0.0092 | 0.0089 | 0.0118 | 4157 | 1.04 | 53 |

dae 各行为 **kdae 分支构建**(`2a007b39`,`unstable-20260729.r987`,
在压测机上从 `../dae` 构建)。其 QUIC 行比 07-28 旧二进制慢约 18–20%
(hy2 3058 → 2511、tuic 3335 → 2669——新合入的 26 个提交,含
routing-epoch 重构,付出了吞吐代价);ss2022/trojan 基本持平。
dae 行复跑过一次确认:除一次 trojan 读数被共享实验室上另一个测试会话
污染外,全部在方差内复现。见"已知的实验室限制"。

² honk hy2/tuic 两行为**修复后**数据:包含 QUIC socket 缓冲(8 MiB
SO_RCVBUF/SO_SNDBUF + rmem_max/wmem_max 提升到 16 MiB)和接收窗口
(8 MiB stream / 32 MiB conn)改动。修复前同样跑法为 hy2 1918 /
tuic 2073 Mbps——瓶颈是 208 KiB 默认 socket 缓冲,不是引擎数据面。

¹ **AnyTLS 单流 iperf3 异常(实验室假象,非引擎回退)**:本实验室内单流
iperf3 过 AnyTLS 只有 2–3 Mbps。原因在服务端一侧——iperf3-daemon ↔
anytls-server 的环回投递(iperf3 进入 app-limited 后不再喂数据)。用
sing-box 客户端打同一批服务端可以复现,而 curl、python 和并发流都能跑满。
用 `iperf3 -P 8` 实测:**anytls-sb 4754 Mbps、anytls-go 3554 Mbps**。

### 结果解读

- **带宽**:honk trojan 领先(4427 vs 4157,+6%),QUIC 协议接近
  (hy2 2289 vs 2511,−9%;tuic 2383 vs 2669,−11%——socket 缓冲/窗口
  修复后的 quinn-vs-quic-go 残余差距,后续 profiling 再收),ss2022
  接近(1314 vs 1528)。
- **延迟**:极端案例是 TUIC:热开流 3.3 ms vs dae 78.6 ms——honk 的
  BoringSSL QUIC 后端有进程级 TLS 1.3 票据缓存,热 TUIC 拨号只要 1 个 RTT;
  dae 每条连接都要完整 QUIC 握手。冷启动同样(10.9 vs 86.5 ms)。其他行在
  几 ms 内互有胜负(共享设施上 ms 级噪音)。
- **CPU**:honk 在每个协议上都以约 1 核跑 multi-Gbps;dae 在 QUIC 协议上
  需要约 1.45 核。
- **内存**:honk 稳态 RSS 14–16 MB,dae 46–64 MB,约 3–4 倍差距。

### 更早的结果

2026-07-29 的几轮(honk beta.22/beta.23,含与 sing-box 1.13.14 的三方对比,
以及 dev@1715d86 的 inline 改动后复测)已被上表取代。依然成立的结论:honk
约 1 核的 CPU 曲线、约 4 倍内存优势,以及对 sing-box 的 trojan/tuic 领先。
ss2022 codec 重写(单流 0.87 → 1.33 Gbps)已包含在上表 1314 Mbps 中。

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
- 发布 CI(`.github/workflows/release.yml`)——workspace 测试门禁 +
  四目标构建(x86_64/aarch64 × gnu/musl)+ BTF 检查 + tarballs。
