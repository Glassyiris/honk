# honk

[English](./README.md) | [中文](./README_CN.md)

---

## 中文

**honk** 是面向 Linux 的 Rust 透明代理引擎，**受** [dae](https://github.com/daeuniverse/dae)（eBPF 数据面与配置形态）与 [sing-box](https://github.com/SagerNet/sing-box)（出站组、多协议拨号、Clash 兼容 API）**启发**。

它**不是**任一上游的逐行移植：内核路径对齐 dae 的 TC + match_set + `dae0`/`daens` 模型；用户态出站与控制面更接近 sing-box 取向的设计。

> **当前状态：实验版本（`v0.0.1.alpha`）。** honk 处于早期 alpha 阶段——接口与行为可能随时变动，部分功能尚未完成（见 TODO），真实环境验证有限，不建议用于生产环境。

许可证：**GPL-3.0-only**。

### 文档

| 文档         | English                                              | 中文                                                 |
| ------------ | ---------------------------------------------------- | ---------------------------------------------------- |
| 设计         | [doc/design.en.md](./doc/design.en.md)               | [doc/design.zh.md](./doc/design.zh.md)               |
| 配置         | [doc/configuration.en.md](./doc/configuration.en.md) | [doc/configuration.zh.md](./doc/configuration.zh.md) |
| 组件详细配置 | [doc/components.en.md](./doc/components.en.md)       | [doc/components.zh.md](./doc/components.zh.md)       |
| 索引         | [doc/README.md](./doc/README.md)                     | 同上                                                 |

### 架构（crate）

```text
crates/
├── honk-core/          # 引擎二进制：控制面、DNS、中继、Clash API、eBPF 挂载
├── honk-config/        # 配置 schema + dae 语法解析 + 分享链接
├── honk-outbound/      # 协议 Handler、组、健康检查
├── honk-ebpf-common/   # 内核/用户态共享 no_std #[repr(C)] 类型
└── honk-ebpf/          # 内核 eBPF 程序（bpfel-unknown-none；不在 workspace 内）
```

高层路径：**TC 分类 → 经 `dae0`/`daens` redirect → sk_lookup 透明监听 → 用户态拨号/中继**。细节见设计文档。

### 与 dae 的差异（eBPF / 控制面）

honk 沿用 dae 的内核模型，但并非移植。主要不同点：

**eBPF 数据面**

- 工具链：Rust [aya](https://github.com/aya-rs/aya)（内核侧 `aya-ebpf`），而非 Go `cilium/ebpf`。
- LAN/WAN 投递与 dae 同构，并非重写：TC 程序给代理流量打标并重定向进 `dae0` veth，随后 `daens` 命名空间内的 `sk_lookup` + `bpf_sk_assign` 把报文交给透明监听 socket。与 Go dae 一样，**不安装任何全局 `iptables` `TPROXY` 规则**。
- 内核侧按出站统计：TC 程序维护 per-CPU `OUTBOUND_STATS` 数组（每出站的 tx/rx 包数/字节数）；dae 的内核路径没有按出站的计数器。
- 路由快路径：推送规则时，用户态按四个 `(l4proto, ipversion)` 组（TCP4/TCP6/UDP4/UDP6）为每条规则链预计算组掩码写入 `ROUTING_META_MAP`，eBPF 路由循环可直接跳过不可能命中该报文组的整条规则链。dae 的 `route()` 顺序评估每个 match set；除此之外核心状态机是 1:1 移植。
- Map 设计：conntrack / redirect-track / routing-handoff 均为 **LRU** hash map（满了自动淘汰最旧条目），dae 则是普通 hash map + 溢出计数；LPM trie 容量限制为 64K 条（每个约 1.3 MB），dae 为 2M。

**控制面**

- 管理 API：sing-box 风格的 **Clash 兼容 REST/WS API**，而非 dae 的 GraphQL（`daed`）。
- 组：sing-box 语义 — 确定性选择、嵌套子组、URLTest 的 TCP/UDP 独立选择、LoadBalance 轮询、Fallback 固定首选；dae 的组是扁平的、基于延迟的固定策略。
- 嗅探：TLS SNI / HTTP Host 之外，还支持 **QUIC Initial SNI 解密**（去头部保护 + crypto 流重组）；dae 只嗅探 TLS/HTTP。
- 持久化：SQLite `cachedb`（Selector 选择、clash 模式、可选 DNS 应答）—— dae 不跨重启保存这类状态。
- 重载/订阅：热重载经同一条串行流水线重建组管理器并迁移 Selector 选择；订阅节点仅在内存合并，不回写配置文件。

### 作者与分工说明

在评价代码归属或 review 责任前请先阅读：

| 范围                                                                                       | 项目维护者的角色                                                      |
| ------------------------------------------------------------------------------------------ | --------------------------------------------------------------------- |
| **eBPF 数据面**（`honk-ebpf`、`honk-ebpf-common`，以及 `honk-core` 中的挂载/map 路径）     | **重点参与** — 设计、校验与实现把关                                   |
| **其余部分**（配置解析、出站协议、组/健康检查、用户态 DNS、Clash API、大量控制面粘合代码） | **主要由 AI 编写**；维护者仅做了**部分代码 review**，并非逐行全量所有 |

这是面向用户与后续贡献者的明确披露。

### 已完成并验证（摘要）

状态对应当前代码树与单测/集成测试。请在本机再跑 `cargo test --all` 作为实时门禁。

#### eBPF / 数据面（维护者重点）

- [x] TC LAN/WAN 入出方向（L2/L3），bond/bridge 从接口挂载
- [x] `dae0` / `dae0peer` + `daens` 投递，`sk_lookup` + SockMap 监听
- [x] MatchSet 路由机、LPM（目的/源/MAC）、域名位图、must/OR/AND 索引
- [x] Conntrack / redirect track / routing handoff map
- [x] cgroup cookie→pid，供进程名规则
- [x] DNS 快路径（DNS 进用户态，跳过完整路由环）
- [x] 每出站 `OUTBOUND_STATS` + `EVENT_RINGBUF` 消费
- [x] 用户态健康检查推送连通性 map
- [x] 无特权测试用的 Mock eBPF 后端

#### 配置与路由（用户态）

- [x] dae 语法加载、include/glob 组合与校验
- [x] 分享链接解析（ss/ssr/vmess/vless/trojan/anytls/hy2/tuic/juicity/…）
- [x] 用户态 `Router`（域名/IP/端口/协议/进程/MAC/geosite/geoip）
- [x] TCP 嗅探（TLS SNI、HTTP Host）；QUIC Initial SNI 解密
- [x] 拨号模式 `ip` / `domain` / `domain+` / `domain++`
- [x] 内置 `direct` 节点注入；`block` 出站

#### 出站与组

- [x] Handler：Direct、Block、SOCKS5、SS（含 2022）、SSR、Trojan、Trojan-Go、VMess、VLESS、Hysteria2、TUIC、Juicity、AnyTLS
- [x] 共享传输层（TLS/WS/gRPC）+ h2mux（`node.mux`）
- [x] 组：Selector / URLTest / LoadBalance / Fallback + 嵌套组
- [x] URLTest：tolerance、TCP/UDP 独立选择、idle_timeout、interrupt_connections
- [x] `AliveDialerSet`：并发探测、恢复滞后、TCP+UDP 探测、推送 eBPF
- [x] 订阅拉取 + 后台合并（节点仅内存）

#### 控制面扩展

- [x] TCP `splice` 中继（失败回退 copy）；UDP anyfrom 回包
- [x] Clash 兼容 REST/WS API（proxies、delay、connections、traffic、logs、DNS query、UI 下载）
- [x] SQLite 缓存（Selector 选择、模式、可选 DNS 持久化）
- [x] 热重载重建 `GroupManager` 并迁移 Selector 选择

#### 测试 / 示例

- [x] `honk-config` / `honk-outbound` / `honk-core` 大量单测与集成测试（请运行 `cargo test --all`）
- [x] 示例配置保持可解析（`example.dae`、`config.dae`、`config.min.dae`）
- [x] 需 root 的 netns/podman 脚本（`scripts/`，依赖环境）

### TODO

- [ ] VMess / VLESS / SSR / Trojan-Go 的 UDP 中继
- [ ] REALITY + uTLS（**已延期** — rustls 缺成熟 hook）
- [ ] smux/yamux；h2mux 与官方 sing-box multiplex inbound 的验证互通
- [x] 真正的 DoT/DoH/DoQ/DoH3 上游（TLS/H2/QUIC 会话复用）
- [x] Hysteria2 brutal（上下行 Mbps）、端口跳跃（`mport`/`mhop`）、`pinSHA256`、QUIC 接收窗口/PMTUD 参数；已对官方服务器实测验证
- [ ] Hysteria2 残留：`maxStreamReceiveWindow`/`maxConnReceiveWindow`（quinn 无自动调窗对应）、`fastOpen`、UDP 会话/连接空闲超时可配（当前硬编码 90s/120s）
- [x] QUIC 客户端选项整合：`QuicClientOptions` 管传输调优，`BoringQuicOptions` 管 TLS 后端
- [ ] FakeIP 引擎
- [ ] 内核侧 eBPF DNS 应答缓存（用户态缓存已有）
- [ ] 一致性哈希负载均衡（轮询 LoadBalance 已有）
- [ ] 对生产环境对端的更广 live 互通测试；root netns 门禁例行化

### 环境要求

- Rust（edition 2024 / 较新 stable；eBPF 目标文件构建需要 **nightly** + `bpf-linker`）
- 真实 eBPF 需要 Linux 内核 **5.8+**
- eBPF 构建需要 `clang`、`llvm`、`libbpf` 头文件

```bash
# Debian/Ubuntu 示例
sudo apt-get install -y clang llvm libbpf-dev build-essential pkg-config
```

### 快速开始

```bash
# 工作区
cargo build --release
cargo test --all

# 真实 eBPF 引擎（需 root）
cargo build --release -p honk-core --features ebpf
sudo ./target/release/honk-core --config /etc/honk/config.dae

# 开发：无内核 eBPF
cargo run --release -p honk-core -- --config config.dae --mock-ebpf
```

日常任务见 `Justfile`（`just build-core`、`just run`、`just clean-all` 等）。

### Docker

默认镜像构建不含 `ebpf` feature（mock 后端）。真实 eBPF 需在构建阶段加 `--features ebpf`（nightly + bpf-linker），或运行时传 `--bpf-object`。

```bash
docker compose up -d
# privileged、host 网络、挂载 /sys 与 /etc/honk — 见 docker-compose.yml
```

### 配置（示意）

```dae
global {
    tproxy_port: 12345
    lan_interface: eth0
    dial_mode: domain
}

node {
    trojan-node: 'trojan://secret@example.com:443'
}

group {
    proxy {
        filter: name(keyword: 'node')
        policy: min_moving_avg
    }
}

routing {
    domain(suffix: google.com) -> proxy
    fallback: direct
}
```

完整说明：[doc/configuration.zh.md](./doc/configuration.zh.md)、[doc/components.zh.md](./doc/components.zh.md)。

### 致谢

- [dae](https://github.com/daeuniverse/dae) / [daed-rs](https://github.com/daeuniverse/daed-rs) — eBPF 透明代理谱系
- [sing-box](https://github.com/SagerNet/sing-box) — 出站组与 Clash API 模式
- [daeuniverse/outbound](https://github.com/daeuniverse/outbound) — 协议参考
- [aya-rs](https://github.com/aya-rs/aya) — Rust eBPF

### 许可证

```text
SPDX-License-Identifier: GPL-3.0-only
Copyright (c) 2025, glassyiris <honk@catmint.cc> and honk contributors
```
