# Benchmark 实验环境与结果

本文档描述 honk 可复现的 benchmark 环境、测量方法学,以及与
[dae](https://github.com/daeuniverse/dae) 的同时刻 A/B 最新结果。文档放在仓库里,
以便实验方法和数据与代码保持同步。

## 实验拓扑

```text
┌─────────────────────────────┐         ┌─────────────────────────────┐
│ 10.10.10.57 (VM, 4C/2G;换 host CPU 前是 .50)     │         │ 10.10.10.70 (物理机, 50G)   │
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

- **引擎机(10.10.10.57)**:同一时刻只运行 honk 或 dae 之一。客户端在
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
- **引擎 VM 的 CPU 已改为 host 透传(i5-13600K,AES-NI + AVX2)**。
  之前是 qemu64 无 SIMD——所有 QUIC 加密都是软件实现(honk 的 BoringSSL
  回落到 `nohw` C 版 ChaCha20-Poly1305,占引擎 CPU 34%),QUIC 带宽被压
  在 ~2–2.4 Gbps。有了 AES-NI 后,下面的数字才代表生产硬件的真实水平。
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
- **udp**——每协议:echo RTT(对路由 echo 端口 5353x 发 15 个 ping 取
  中位数)和 iperf3 `-u -b 10G -l 1200 -R`(饱和供给下的接收带宽 +
  丢包率;数据报固定 1200B,因为 QUIC datagram 上限就在那附近)。
- **cpu**——中位数带宽那一轮期间的引擎 CPU 核数
  (`/proc/<pid>/stat` utime+stime 差值除以墙钟时间)。honk 的 pid 锚定
  clash API 监听者,停在单实例锁上的第二实例(零 CPU)不会污染指标。
- **rss**——带宽轮结束后的引擎 RSS。
- **direct 基线**——同样方法测量未代理路径(`8080`/`5300`)。

```bash
scp bench/lab-bench.sh root@10.10.10.57:/root/
ssh root@10.10.10.57 "bash /root/lab-bench.sh 'honk dae' 'hy2 tuic ss2022 trojan anytls-sb anytls-go'"

# 协议正确性矩阵(每协议 TCP 目标 / UDP echo / 外网)
ssh root@10.10.10.57 bash /root/test-protocols.sh
```

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
会话灌死 sid 的 PSH 垃圾帧。修复为真正的有界 HOL 背压(队列满时 demux
最多等 5s 再杀)。anytls-go 现在与 dae 持平;anytls-sb 落后(sing-box
服务端的帧模式 dae 容忍得更好——后续工作)。

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
