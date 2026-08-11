# honk 组件详细配置参考

各主要组件的字段级说明，配合 [configuration.zh.md](./configuration.zh.md) 使用。

配置文件使用 **dae 语法**（`include { ... }`、`global { ... }`、`node { ... }`、`group { ... }`、`routing { ... }`、`dns { ... }`、`subscription { ... }`、`experimental { ... }` 各节）。`include` 用于组合 `.dae` 文件，路径与合并规则见 [configuration.zh.md](./configuration.zh.md#拆分配置文件)；完整示例见仓库根目录的 `config.dae` 与 `config.min.dae`。

权威来源：`crates/honk-config/src/*`（dae 解析器在 `crates/honk-config/src/parser/`）、`crates/honk-outbound/src/proxy/`、`crates/honk-core` CLI。

表中标注「结构化模型字段，dae 语法无对应键」的条目存在于配置数据模型中，但 dae 解析器不读取同名键，无法通过 dae 语法设置。

---

## 1. Global（`global { ... }`）

| 字段 | 类型 | 默认值 | 含义 |
| ------ | ------ | -------- | ------ |
| `tproxy_port` | u16 | `12345` | 透明监听端口 |
| `tproxy_mark` | u32 | `0x08000000` | fwmark（结构化模型字段，dae 语法无对应键） |
| `tproxy_port_protect` | bool | `true` | 避免代理 TPROXY 端口自身 |
| `pprof_port` | u16 | `0` | pprof HTTP 端口；`0` = 关闭 |
| `so_mark_from_dae` | u32 | `0` | honk 打开套接字的可选 SO_MARK |
| `log_level` | string | `"info"` | `trace`/`debug`/`info`/`warn`/`error` |
| `disable_waiting_network` | bool | `false` | 启动时不等待网络就绪 |
| `lan_interface` | string[] | `[]` | 拦截的 LAN 网卡；空时不安装任何 LAN hook；逗号分隔 |
| `wan_interface` | string[] | `[]` | 拦截本机发起 TCP/UDP 的 WAN 网卡；`auto` 跟随 IPv4 默认路由。默认路由不存在时保持待定（不会回退到 `lo`），并在网卡、地址或路由事件后自动挂载；同一事件还会重新发布网关本机地址的 `direct(must)` 规则，并立即复测受健康状态控制的出站。 |
| `auto_config_kernel_parameter` | bool | `false` | 自动 sysctl（需 root） |
| `data_dir` | string | `"/var/share/honk"` | 生成状态与相对运行时资源的绝对根目录；不能为空，修改后需重启进程。 |
| `store_subscribe` | bool | `true` | 将每个订阅最近一次有效正文持久化到 `global.data_dir` 下的 `.sub`，供启动/重载在网络不可用时恢复；已有 `./.sub` 会继续使用，直至手动迁移；修改后需重启进程。 |
| `tcp_check_url` | string[] | gstatic HTTPS | TCP 健康检查目标；HTTPS 会先完成并校验目标 TLS，再发送配置的 HTTP 方法。 |
| `tcp_check_http_method` | string | `"HEAD"` | URL 检查的 HTTP 方法 |
| `udp_check_dns` | string[] | dns.google / 8.8.8.8 / IPv6 | UDP 健康检查 DNS 目标；逗号分隔 |
| `check_interval_secs` | u64 | `30` | 检查间隔（秒）。**dae：** `check_interval` 时长（如 `300s`） |
| `check_tolerance_ms` | u64 | `50` | URLTest 切换阈值（ms）。**dae：** `check_tolerance`（如 `30ms`） |
| `dial_mode` | string | `"domain"` | `ip` / `domain` / `domain+` / `domain++` |
| `allow_insecure` | bool | `false` | 全局 TLS 跳过校验回退 |
| `sniffing_timeout_ms` | u64 | `30` | 嗅探超时（ms）。**dae：** `sniffing_timeout` 时长 |
| `tls_implementation` | string | `"tls"` | TLS 栈：`tls`（原生 BoringSSL）/ `utls`（真实 Chrome 指纹） |
| `utls_imitate` | string | `"chrome_auto"` | 指纹配置；`chrome*` 映射到内置真实 Chrome 指纹（BoringSSL）；其他值告警并回退 Chrome（目前唯一 profile） |
| `tls_fragment` | bool | `false` | TLS ClientHello 分片开关 |
| `tls_fragment_length` | string | `""` | 分片长度范围 |
| `tls_fragment_interval` | string | `""` | 分片间隔范围 |
| `mptcp` | bool | `false` | 拨号启用 MPTCP |
| `bootstrap_resolver` | string | `""` | 解析**节点主机名**（避免环路） |
| `fallback_resolver` | string | `"8.8.8.8:53"` | 控制面回退 DNS |
| `bandwidth_max_tx` / `bandwidth_max_rx` | string | `""` | 带宽提示（如 `'200 mbps'`） |
| `udphop_interval_secs` | u64 | `30` | UDP hop 间隔（结构化模型字段，dae 语法无对应键） |
| `connect_timeout_ms` | u64 | `3000` | TCP 连接超时（结构化模型字段，dae 语法无对应键） |
| `dns_resolve_timeout_ms` | u64 | `2000` | 控制面解析超时（结构化模型字段，dae 语法无对应键） |
| `relay_idle_timeout_secs` | u64 | `300` | 空闲中继断开；`0` = 关闭（结构化模型字段，dae 语法无对应键） |
| `preconnect_node_count` | usize | `'auto'` | 启动时执行一轮裸 TCP 预连接。`'auto'` 最多尝试 8 个节点；`0` 关闭；显式 `N` 可覆盖所有合格节点，但最多 8 个并发尝试。候选按各组当前选择、再按配置顺序；仅可池化裸 TCP 的协议入选（AnyTLS、VLESS H2MUX/Mux.Cool、QUIC 与内置 `direct`/`block` 排除）。 |
| `udp_warm_node_count` | usize | `0` | 每组 UDP 预热上限。`0` 严格关闭。正值 N 取各组延迟 top `min(N,3)` 的 UDP 叶子；独立 coordinator 启动后立即运行，随后每批完成再等待一个 `check_interval`，最多并发四个尝试。可复用的 VLESS H2MUX/Mux.Cool 状态会参与；合并候选按全局 UDP 延迟重排，进程驻留总量封顶 `4×N`。 |
| `max_concurrent_dials` | usize | `64` | 按 runtime generation 生效的物理代理连接与协议握手并发上限，另受所有重叠 reload generation 共享的启动时描述符 gate 约束。Ready 池命中、已热 AnyTLS/VLESS-H2MUX/VLESS-Mux.Cool/QUIC transport 上的逻辑流，以及内置 `direct`/`block` 均不占额度。replacement generation 立即采用新值；旧 generation 中进行中的拨号继续占用同一个进程级 gate，直至结束。 |

### 拨号模式细节

| 模式 | 嗅探 | 域名校验 | 按嗅探重路由 |
| ------ | ------ | ---------- | -------------- |
| `ip` | 否 | 不适用 | 否 |
| `domain` | 是 | 是（须解析到目的 IP） | 否 |
| `domain+` | 是 | 否 | 否 |
| `domain++` | 强制 | 否 | 是 |

---

## 2. 节点（`node { ... }`）

dae 语法中节点**只能以分享链接书写**：`tag: 'scheme://...'` 或裸 `'scheme://...'`（名称取自 `#fragment` 或 `{scheme}-{host}`）。下表是链接解析后填充的节点模型字段。

### 通用字段

| 字段 | 类型 | 默认值 | 含义 |
| ------ | ------ | -------- | ------ |
| `id` | UUID | 内容派生 | 稳定身份：对 `protocol\|host\|port\|credential\|dial-shape`（dial shape = sni/transport/ws/grpc/obfs 外加 REALITY/flow 握手形态与非 legacy VLESS mode）取 UUID v5；改名不变，两个节点派生出相同 id 会被拒绝（订阅内重复端点跳过并告警） |
| `name` | string | **必填** | 路由 / API 名称；dae 中为链接前的 tag |
| `protocol` | enum | `ss` | 见协议表；dae 中由链接 scheme 决定 |
| `address` | string | 必填* | 主机或 `host:port` |
| `host` | string | `""` | 显式主机；否则从 `address` 取 |
| `port` | u16 | `0` | 服务端口 |
| `username` / `password` | string? | null | 认证 / UUID / 密钥；链接 userinfo |
| `encryption` | string? | null | SS/VMess 加密，或 Xray VLESS Encryption 客户端字符串（分享链接 `encryption=`） |
| `vless_mode` | `WireMode` | `legacy` | `legacy` / `uot-v2` / `h2mux` / `h2mux-padded` / `xudp` / `mux-cool`；分享链接参数 `vless_mode=` |
| `plugin` / `plugin_opts` | string? | null | 插件名/参数；链接 `plugin` / `plugin-opts` |
| `transport` | string | `"tcp"` | `tcp` / `ws` / `grpc` / …；链接 `type`（或 `network`）参数 |
| `tls` | bool | `false` | 启用 TLS；trojan/vless/anytls 等链接自动开启 |
| `sni` | string? | null | TLS SNI；链接 `sni`（或未被传输占用的 `host`）参数 |
| `skip_cert_verify` | bool | `false` | 跳过证书校验；链接 `allowInsecure` / `insecure` 参数 |
| `ech_enabled` | bool | `false` | 提供 ECH；链接 `ech=1`（或 `ech_config` 隐式开启） |
| `ech_config` | string? | null | Base64 编码的 ECHConfigList；链接 `ech_config` 参数 |
| `ech_config_path` | string? | null | 存放 base64 ECHConfigList 的文件路径；相对路径优先读取 `<global.data_dir>/<path>`，不存在时兼容旧的工作目录相对文件。 |
| `reality_public_key` | string? | null | REALITY 服务端 X25519 公钥（分享链接 `pbk`）；设置后该节点走 REALITY 握手而非普通 TLS（`security=reality` 隐含 `tls=true`） |
| `reality_short_id` | string? | null | REALITY short id（链接 `sid`，偶数长度 hex，至多 8 字节） |
| `reality_spider_x` | string? | null | REALITY spider 路径（链接 `spx`，链接约定默认 `/`） |
| `flow` | string? | null | VLESS flow 控制（链接 `flow=`）；仅支持 `xtls-rprx-vision`，要求 TLS 或 REALITY 承载；非 legacy 模式中只有 `xudp` 可以使用——由 `Config::validate` 强制校验 |
| `network` | string? | null | V2Ray 风格 network 提示 |
| `ws_path` / `ws_host` | string? | null | WebSocket；链接 `path` / `host` 参数 |
| `grpc_service` | string? | null | gRPC service 名；链接 `serviceName` 参数 |
| `hy2_auth` / `hy2_obfs` | string? | null | Hysteria2 认证 / salamander 混淆密码 |
| `hy2_up_mbps` / `hy2_down_mbps` | u32? | null | Hysteria2 brutal 带宽（`upmbps`/`downmbps`） |
| `hy2_port_hopping` / `hy2_hop_interval` | string? / u64? | null | Hysteria2 端口跳跃（`mport`/`mhop`） |
| `hy2_init_stream_recv_window` / `hy2_init_conn_recv_window` | u64? | null | Hysteria2 QUIC 接收窗口 |
| `hy2_disable_mtu_discovery` | bool? | null | Hysteria2 `disablePathMTUDiscovery` |
| `tls_pin_sha256` | string? | null | 叶证书 SHA-256 固定（`pinSHA256=`） |
| `tuic_uuid` / `tuic_password` / `tuic_congestion` | string? | null | TUIC |
| `tuic_init_stream_recv_window` / `tuic_init_conn_recv_window` | u64? | 8 MiB / quinn 默认 | TUIC QUIC 接收窗口；8 MiB 流窗口默认值提升高 RTT 链路单流吞吐（quinn 默认 1.25 MiB 每 100ms RTT 封顶约 12.5MB/s） |
| `juicity_uuid` / `juicity_password` | string? | null | Juicity |
| `anytls_password` | string? | null | AnyTLS 密钥（等于链接密码） |
| `anytls_min_idle_session` | usize? | null（实际为 0） | 显式池待机会话下限；链接 `min_idle_session`。Selector 当前叶节点会独立把有效下限提升到至少 1；其他节点设为 `0` 时可回收全部空闲会话。 |
| `anytls_idle_session_check_interval` | u64? | null | 空闲检查周期（秒）；链接 `idle_session_check_interval` |
| `anytls_idle_session_timeout` | u64? | null | 空闲驱逐（秒）；链接 `idle_session_timeout` |
| `mark` | u32? | null | 出站 SO_MARK（结构化模型字段，dae 语法无对应键） |
| `tags` | string[] | `[]` | 标签（结构化模型字段，dae 语法无对应键） |
| `subscription_id` / `group_id` | UUID? | null | 归属元数据（运行时填充） |
| `created_at` / `updated_at` | datetime | now | 元数据（运行时填充） |

\* 校验要求：`name` 非空，且 `address` 或 `host` 非空。

### 协议

| 取值 | 别名 | TCP | UDP | 说明 |
| ------ | ------ | ----- | ----- | ------ |
| `ss` | `shadowsocks` | 是 | 是 | AEAD + `2022-blake3-*` |
| `trojan` | | 是 | 是 | TLS；经 transport 支持 WS/gRPC |
| `vmess` | | 是 | 否 | AEAD；WS/gRPC；`security=reality` 可启用 REALITY；仅在 `rprx` feature 下注册（honk-core 默认构建开启） |
| `vless` | | 是 | 取决于模式 | Xray VLESS Encryption；REALITY + `xtls-rprx-vision`；UoT v2、sing-box H2MUX、Xray Single XUDP 或池化 Mux.Cool UDP；经 transport 支持 WS/gRPC；仅在 `rprx` feature 下注册 |
| `socks5` | | 是 | 是 | UDP ASSOCIATE |
| `hysteria2` | | 是 | 是 | 真实 QUIC/H3；salamander；brutal（配带宽时）或 BBR；端口跳跃 |
| `tuic` | | 是 | 是 | TUIC v5 / quinn |
| `juicity` | | 是 | 是 | quinn 双向流 UDP |
| `anytls` | | 是 | 是 | 会话池 + UoT v2 |
| `direct` | | 是 | 是 | 内置直连出口；保留协议，加载时注入（不可配置） |
| `block` | | — | — | 内置拒绝出口；保留协议，加载时注入（不可配置） |

内置 **`direct`** 与 **`block`** 节点在加载时注入（配置中可不写）；用户节点不得占用其名称或协议。

### 协议提示

**Shadowsocks 2022**

- 方法：`2022-blake3-aes-128-gcm`、`2022-blake3-aes-256-gcm`、`2022-blake3-chacha20-poly1305`
- 密码：base64 PSK — aes-128-gcm 为 16 字节，其余 32 字节

**Trojan / VMess / VLESS 传输**

dae 语法下经分享链接 query 传递传输与 TLS 参数：

```
node {
    my_ws:   'trojan://password@example.com:443?type=ws&path=/path&host=example.com&sni=example.com#my_ws'
    my_grpc: 'trojan://password@example.com:443?type=grpc&serviceName=GunService&sni=example.com#my_grpc'
}
```

已实测互通的 VLESS 组合（对 sing-box 1.13 服务端）：TCP+REALITY+vision、TCP+REALITY、TCP+WS、TCP+WS+TLS、TCP+gRPC。`xtls-rprx-vision` flow 仅与 TCP+REALITY/TLS 组合——WS/gRPC 下没有可供 XTLS direct-copy 切换的裸连接，与上游一致。

Clash 订阅会在派生节点身份前把 VLESS 的 `uuid`、`encryption`、
`servername`/`sni`、`flow`、`network` 以及嵌套 `reality-opts`、`ws-opts`、`grpc-opts` 映射到
同一组节点字段；不完整的 `reality-opts` 条目直接跳过。TCP/WS/gRPC
以外的传输、非 Vision flow、缺少 TLS/REALITY 的 Vision，以及经
WS/gRPC 的 Vision 会由 `honk-tool sub` 显示但不探测。
`client-fingerprint` 不是节点字段，由全局 TLS 模式统一控制。

#### VLESS mode

`Node.vless_mode` 是唯一的 `WireMode`：必须显式选择、互斥且不协商。

| 取值 | TCP | UDP | 行为 |
| ------ | ----- | ----- | ------ |
| `legacy` | 原有 VLESS stream | 否 | 保持兼容的默认值；旧节点 ID 不变 |
| `uot-v2` | 原有 VLESS stream | 直连 UoT v2 | 每个 UDP transport 一条 connected UoT stream；不套复用层 |
| `h2mux` | H2MUX 逻辑 stream | sing-mux 原生 connected UDP | TCP 与 UDP 共用节点所有的 HTTP/2 carrier pool |
| `h2mux-padded` | H2MUX 逻辑 stream | sing-mux 原生 connected UDP | 在 `h2mux` 基础上启用 sing-mux v1 padding |
| `xudp` | 原有 VLESS stream | Single XUDP | 每个 UDP transport 一条 VLESS mux-command carrier，使用 XUDP session id 0；TCP 保持普通路径 |
| `mux-cool` | Mux.Cool 逻辑 stream | 池化 XUDP | 逻辑 TCP 与 UDP 共用节点所有的 Xray Mux.Cool carrier pool |

规范 dae 配置仍写在 VLESS 分享链接内：

```dae
node {
    vless_mux: 'vless://uuid@example.com:443?security=tls&vless_mode=h2mux#vless_mux'
    vless_cool: 'vless://uuid@example.com:443?security=reality&pbk=...&sid=ab12&vless_mode=mux-cool#vless_cool'
}
```

H2MUX 与 Mux.Cool 每个节点都最多使用两条物理 carrier、每条最多 128 个逻辑 stream。H2MUX 保留 HTTP/2 flow control、half-close/reset、GOAWAY 滚动与可选 v1 padding。Mux.Cool 用一个有序 writer 串行化全部子帧，session id 永不复用，支持 full-cone UDP 回包源地址，并在发出 128 个 id 后滚动 carrier。两种 pool 都会在未变节点重载时复用，失去所有权后只排干可复用状态，不切断活动子连接。Single XUDP 明确不入池。饱和时等待；speculative loser 永不发布；所有模式都不探测、不降级，也不重放首包。

所有非 `legacy` 模式都拒绝非 `none` VLESS Encryption。`flow=xtls-rprx-vision` 只能与 `legacy` 或 `xudp` 组合；其他模式会接管不兼容的内层 framing。规范分享链接使用 `vless_mode`；兼容参数 `packetEncoding=xudp` 会导入为 `xudp`，而含义有歧义的 `smux`、`multiplex`、`udp-over-tcp`、`packet-encoding`、`packet-addr`、`xudp` query 会被拒绝。Clash/mihomo YAML 仅在 `protocol: h2mux` 或显式 `padding` 布尔值能够判别 wire mode 时，才把已启用的 `smux`/`multiplex` 导入为 H2MUX；两者都缺失的已启用配置会被拒绝。`udp-over-tcp` 版本 0/2 导入为 UoT v2，`packet-encoding: xudp` 或 `xudp: true` 导入为 Single XUDP；冲突表示、packetaddr、不支持的 mux 协议/调优，以及没有显式 packet mode 的 `udp: true` 都会被拒绝。`mux-cool` 当前必须使用规范分享链接模式。官方 live 互通覆盖 sing-box 的 UoT/H2MUX，以及 Xray 的 Single XUDP/Mux.Cool，并包含 TLS、REALITY、padding 与 XUDP Vision。

**VLESS Encryption**

把分享链接的 `encryption=` query（或结构化配置的 `Node.encryption` 字段）设为 `xray vlessenc` 生成的客户端字符串：

```dae
node {
    vless_e: 'vless://uuid@example.com:443?security=none&encryption=mlkem768x25519plus.native.0rtt.<base64url-公钥>#vless_e'
}
```

客户端支持 Xray 的 `native`、`xorpub`、`random` 三种 wire mode；X25519 或 ML-KEM-768 认证密钥（含链式多密钥）；每连接 ML-KEM-768 + X25519 前向保密；以及 `1rtt` 或基于缓存 ticket 的 `0rtt`。payload record 在硬件加速可用时使用 AES-256-GCM，否则使用 ChaCha20-Poly1305。VLESS Encryption 位于所选 TCP/TLS/REALITY/WS/gRPC transport 内层，但不能与 `xtls-rprx-vision` 组合。已对 Xray 26.7.28 的裸 TCP 服务端实测三种模式、两类认证密钥、链式 X25519 密钥及 1-RTT → 0-RTT 切换。

**VLESS + REALITY（xtls-rprx-vision）**

`security=reality` 把 vless（或 vmess）节点从普通 TLS 切换为 REALITY 握手；`pbk`/`sid`/`spx` 携带 REALITY 参数，`flow=xtls-rprx-vision` 启用 XTLS Vision 拼接：

```dae
node {
    vless_r: 'vless://uuid@example.com:443?security=reality&sni=dl.google.com&pbk=<base64url-公钥>&sid=ab12&flow=xtls-rprx-vision#vless_r'
}
```

- 显式 `security=` 覆盖 vless 历史默认的 TLS 开启行为：`security=none` 关闭 TLS，其余取值开启；不带 `security=` 的链接解析行为与之前完全一致（vless 默认开 TLS，vmess 默认关）。`fp=` 被接受但忽略——ClientHello 指纹跟随全局 `tls_implementation` 模式。
- REALITY 不需要 CA，也不需要 `skip_cert_verify`：服务端在握手后基于 REALITY auth key 认证（见 `doc/design.zh.md`），认证失败一律拒绝，不会降级。
- REALITY 的 `dest`/SNI 要选 TLS Certificate 消息小于 8 KiB 的目标（sing-box reality 缓冲为 8192 字节）——`dl.google.com` 可用，`www.microsoft.com` 不可用。
- VMess 与 VLESS 的 handler 由 honk-outbound 的 `rprx` cargo feature 编译（honk-core 默认开启）。不带该 feature 的构建可以解析这类节点，但拨号会以 "No handler for protocol" 拒绝。

### TLS 指纹与 ECH

所有 TLS 均运行在 **BoringSSL** 上（代理 TLS、DoT/DoH 上游，以及经由自研 quinn 加密后端的 QUIC 握手）。两种全局模式：

- `tls_implementation: tls` — 原生 BoringSSL ClientHello。
- `tls_implementation: utls` — 真实 Chrome 指纹：GREASE、扩展乱序、X25519MLKEM768+X25519 密钥分享、Chrome 签名算法/曲线、brotli 证书压缩、h2 ALPS、ECH GREASE。对 TCP TLS 与 QUIC ClientHello 同时生效。

按节点配置 **ECH**（Encrypted Client Hello）——TLS 与 QUIC（hysteria2/juicity/tuic）均可：

```dae
node {
    hy2_ech: 'hysteria2://secret@example.com:443?sni=example.com&ech_config=AD%2B-DQIAA...#hy2_ech'
}
```

- `ech_config=<base64 ECHConfigList>`（或结构化配置中的 `ech_config_path`）提供真实 ECH；无配置时 Chrome 模式发送 ECH GREASE（与真实浏览器一致）。
- ECH 按 RFC 失败关闭：服务端不接受 ECH 时握手失败（BoringSSL `ECH_REJECTED`），服务端提供的重试配置会写入日志。
- `ech_enabled` 但无静态配置时，连接期从 DNS HTTPS 记录（RFC 9460）发现 ECHConfigList——经 bootstrap resolver（未配置时用系统首个 nameserver），按域名缓存（命中按记录 TTL，未命中 5 分钟）。发现是尽力而为且失败开放的：找不到配置时 Chrome 模式仍发送 ECH GREASE，握手不带 ECH 继续。

**AnyTLS 池**

```
node {
    my_anytls: 'anytls://secret@example.com:443?sni=example.com&min_idle_session=3&idle_session_check_interval=30&idle_session_timeout=30#my_anytls'
}
```

**Hysteria2 / TUIC / Juicity**

使用分享链接（`hysteria2://` / `tuic://` / `juicity://`），链接解析后填充 `hy2_*` / `tuic_*` / `juicity_*` 字段。QUIC ALPN/拥塞控制跟随 Handler 默认（无带宽提示时 Hy2 使用 BBR）。hysteria2 链接中 userinfo 为认证密钥（→ `hy2_auth`），`obfs=salamander&obfs-password=<pwd>` 映射到 `hy2_obfs`，`upmbps`/`downmbps` 启用 brutal 发送端并通过 `Hysteria-CC-RX` 通告下行带宽，`mport`/`mhop` 启用客户端端口跳跃（服务端需将端口段 DNAT 到监听端口），`pinSHA256=<hex>` 固定叶证书指纹（替代 PKI/域名校验），`initStreamReceiveWindow`/`initConnReceiveWindow`/`disablePathMTUDiscovery` 调整 QUIC 传输参数：

```dae
node {
    hy2: 'hysteria2://secret@example.com:443?sni=example.com&insecure=1&obfs=salamander&obfs-password=obfspw&upmbps=50&downmbps=200&mport=20000-30000&mhop=30#hy2'
}
```

### 分享链接 scheme

| Scheme | 说明 |
| -------- | ------ |
| `ss://` | SIP002 |
| `vmess://` | base64 JSON（v2rayN） |
| `vless://` / `trojan://` | query 传 transport/TLS；vless/vmess 另支持 `security=reality|tls|none`、`pbk`、`sid`、`spx`、`flow`，VLESS 单独支持规范 `vless_mode=` |
| `anytls://` | query 中的池参数 |
| `hysteria2://` / `tuic://` / `juicity://` | QUIC 族 |
| `socks5://` | 简单代理 |

链式 `a -> b` **只解析第一跳**。名称来自 `#fragment` 或 `{scheme}-{host}`。

---

## 3. 组（`group { ... }`）

dae 语法中每个组是 `group { ... }` 内的命名子节，可写 `filter:`、`policy:`、`default:`、`final:`：

```
group {
    hk {
        filter: name(keyword: '🇭🇰')
        policy: min_moving_avg
        final: direct
    }
}
```

| 字段 | 类型 | 默认值 | 含义 |
| ------ | ------ | -------- | ------ |
| `id` | UUID | 随机 | Id |
| `name` | string | **必填** | 路由中的出站标签；dae 中为子节名 |
| `policy` | enum | `selector` | 选择策略 |
| `nodes` | UUID[] | `[]` | 通常由 filters 填充 |
| `filters` | string[] | `[]` | `name(...)` / `subtag(...)` / `group(...)`；dae 中每条一个 `filter:` 行 |
| `groups` | string[] | `[]` | 嵌套组标签；`filter: group('a', 'b')`，也接受 `'a\|b'` / `'a, b'` |
| `default` | string? | null | Selector 默认节点名 |
| `final_outbound` | string? | null | 全死时出站。**dae：** `final` |
| `check_url` | string? | null | 覆盖全局 TCP 检查 URL（结构化模型字段，dae 语法无对应键） |
| `check_interval` | u64? | null | 覆盖间隔（秒）（结构化模型字段，dae 语法无对应键） |
| `tolerance` | u64 | `50` | URLTest 滞后（ms）；`0` = 任一更优即切（结构化模型字段，dae 语法无对应键；dae 用全局 `check_tolerance`） |
| `check_url` | string | （全局） | 按组自定义探活目标（仅 URLTest 组，sing-box urltest `url`）；dae：`check_url: 'http://...'` |
| `idle_timeout` | u64? | null | 空闲后停止检查（秒）；0/None = 永不（结构化模型字段，dae 语法无对应键） |
| `interrupt_connections` | bool | `false` | 选择变化时打断连接（结构化模型字段，dae 语法无对应键） |
| `created_at` | datetime | now | 元数据 |

### 策略

| 规范名 | 别名 | 行为 |
| -------- | ------ | ------ |
| `selector` | `select`、`fixed`、`fixed(0)` | 手动固定；API + cache。其配置叶节点始终保持热态：AnyTLS/VLESS-H2MUX/VLESS-Mux.Cool 保留可复用 session，QUIC 保留 client，其他代理协议保留一条服务端裸 TCP。 |
| `urltest` | `min_moving_avg`、`min_avg10`、`min_last_delay` | 最低延迟 + tolerance；按减半递推移动平均 `(prev+sample)/2` 排名（dae `min_moving_avg` 语义）；**TCP/UDP 分离** |
| `loadbalance` | `roundrobin`、`round_robin`、`balance` | 每组、每网络独立对存活成员轮询 |
| `fallback` | | TCP/UDP 各自固定第一个存活成员；无立即 failback |

### 过滤解析

1. `group('tag')` → 嵌套标签（`groups`），不进节点列表。
2. `name(...)` 匹配节点名；`subtag(...)` 匹配产生该节点的订阅 tag。两者均支持精确值、`keyword:`、`regex:`，并区分大小写。
3. 同一行内 `&&` 为 AND，支持 `!` 取反；不同 `filter:` 行之间为 OR。
4. 每次订阅刷新都会重建过滤成员；节点 UUID 即使稳定，也不会在更换订阅后错误残留。
5. 无 filters 且无嵌套组 → **全部节点**；仅有嵌套组 → **不是**全部节点。

### 嵌套组

深度上限 8；构图时切断环并告警。拨号始终落到单个**叶子**节点。Clash 的 `all` 显示成员标签；健康检查展开叶子。

---

## 4. 路由（`routing { ... }`）

dae 规则写作 `条件函数 && 条件函数 -> 出站`，按书写顺序匹配并以 `fallback:` 收尾。matcher 的括号参数可跨物理行，仍作为一条规则：

```
routing {
    domain(suffix: google.com) -> proxy
    dip(geoip: cn) -> direct(must)
    sip(10.10.10.24/32,
        10.10.10.25/32
    ) -> direct
    fallback: direct
}
```

| 字段 | 类型 | 默认值 | 含义 |
|------|------|--------|------|
| `rules` | rule[] | `[]` | 有序规则；dae 中按书写顺序 |
| `default_outbound` | string | `"direct"` | 回退。**dae：** `fallback:` / `default:` |

任意 matcher 可加 `!` 前缀取反（仅作用于紧随其后的一个 matcher）：
`sip(10.10.10.24/32) && !dport(53) -> direct(must)`。规则匹配 ⟺ 所有正向
matcher 都匹配且所有取反 matcher 都不匹配。域名未知的流对取反的
domain/geosite matcher 视为"不是 x"，不会被其否决。

### 规则字段

| 字段 | 类型 | 默认值 | 含义 |
| ------ | ------ | -------- | ------ |
| `name` | string | `""` | 显示名（dae 自动 `rule-N`） |
| 条件字段 | 扁平 | | 见下表 |
| `outbound` | string | 必填 | 单个节点/组标签（dae 中 `->` 的右侧） |
| `priority` | u32 | `0` | 越小优先级越高；dae 中按行序自动编号 |
| `must` | bool | `false` | 非终结 must 规则；dae 中写作 `-> direct(must)` |
| `mark` | u32 | `0` | fwmark；`0` = 无（结构化模型字段，dae 语法无对应写法） |

### 条件

| 字段 | 匹配 |
| ------ | ------ |
| `domain` | 完整域名 |
| `domain_suffix` | 后缀 |
| `domain_keyword` | 子串 |
| `domain_regex` | 正则 |
| `ip` | 目的 IP/CIDR |
| `source_ip` | 源 IP/CIDR |
| `port` / `source_port` | 端口（字符串形式） |
| `protocol` | `tcp` / `udp` |
| `process_name` | 进程名（`pname`） |
| `mac` | MAC |
| `geo_ip` | GeoIP 代码（`cn`、`private` 等） |
| `geosite` | Geosite 代码 |
| `ip_version` | IP 版本 |
| `dscp` | DSCP |
| `not` | 取反 matcher 集（`!matcher(...)`），字段与上表完全镜像 |

同一规则上多字段为 AND。dae 用 `&&` 连接函数。

### dae 条件函数

| 函数 | 映射到 |
| ------ | -------- |
| `domain(...)` | domain_* / geosite（经标签） |
| `dip(...)` | `ip` / `geo_ip` |
| `sip(...)` | `source_ip` |
| `dport` / `sport` | 端口 |
| `l4proto` | `protocol` |
| `pname` | `process_name` |
| `mac` / `dscp` / `ipversion` | 同名字段 |

`domain` 参数标签：裸值/`suffix:` → 后缀；`keyword:`；`full:`；`regex:`；`geosite:`（原样匹配；`category@attr` 按条目属性名过滤，同 dae 语义——大小写不敏感，第一个 `@` 之后整体为选择器；展开为零匹配时告警且永不命中）。

---

## 5. DNS（`dns { ... }`）

```
dns {
    # bind: 'tcp+udp://:1053'   # 保持注释即可只用透明 DNS
    ipversion_prefer: 4
    use_host: true
    upstream {
        homedns: 'udp+tcp://10.10.10.1:53'
    }
    routing {
        request {
            fallback: homedns
        }
    }
}
```

### 顶层

| 字段 | 类型 | 默认值 | 含义 |
| ------ | ------ | -------- | ------ |
| `bind` | string | `""` | host netns 中可选的独立 UDP/TCP 监听；空值只关闭此监听 |
| `use_host` | bool | `false` | 先于 DNS 路由、缓存和上游，用 `/etc/hosts` 应答 IN class A/AAAA 查询 |
| `upstream` | list | 一个 `default` @ 223.5.5.5 UDP | 服务器；dae：`upstream { name: 'uri' }` |
| `routing` | object | fallback 默认 | 请求路由；dae：`routing { request { ... } }` |
| `strategy` | enum | 未指定时为 `both`；设置 `ipversion_prefer: 4\|6` 时分别为 `preferipv4`/`preferipv6` | 地址族策略 |
| `cache` | object | 启用 | 缓存；dae：`optimistic_cache` / `optimistic_cache_ttl` / `max_cache_size` |

### hosts 文件

`use_host: true` 时，每次构建 DNS generation 都会读取一次 `/etc/hosts`。每个有效
地址行的规范名和别名都会生效；匹配为精确、ASCII 大小写不敏感，末尾点会归一化，
重复地址会去重，同时支持 IPv4 与 IPv6。无效地址行和注释会被忽略。

`ipv4_only`/`ipv6_only` 的硬地址族过滤仍最先执行。除此之外，已知名称的 IN class
A/AAAA 查询优先于 request 规则（包括 `reject`）、缓存条目和上游。名称存在但缺少所
请求地址族时返回 NOERROR/NODATA，不会把查询泄漏给上游；非地址 qtype 与非 IN class
仍走原路由管线。hosts 应答参与正常的 DNS 路由投影，wire TTL 为 60 秒，且绕过 honk
应答缓存。

加载后的表在该 DNS runtime generation 生命周期内不可变，查询路径不会读文件。
修改 `/etc/hosts` 后需发送 SIGHUP；替换 generation 会原子加载新快照，已取得 lease
的在途请求仍可在旧快照上结束。文件不可读会令启动失败，或在发布前中止 reload 并
保留当前 generation。

### 独立监听

`dns.bind` 只接受下列 dae 兼容形式：

| 值 | 监听 |
| --- | ---- |
| 省略或 `""` | 关闭；透明 TCP/UDP 53 端口拦截仍生效 |
| 数字 `IP:port`，如 `127.0.0.1:1053` 或 `[::1]:1053` | 仅 UDP |
| `udp://host:port` | UDP |
| `tcp://host:port` | TCP |
| `tcp+udp://host:port` | TCP 与 UDP |

带 scheme 的形式可使用主机名（`udp://localhost:1053`）、方括号包裹的 IPv6
字面量（`tcp://[::1]:1053`），或用空 host 表示通配地址
（`tcp+udp://:1053`）。端口必须显式给出；`0` 表示申请临时端口，最终地址会写入
日志。裸主机名、userinfo、path、query、fragment 和 IPv6 zone identifier 均无效。
主机名选择第一个能让全部请求 transport 成功 bind 的解析地址。

这些是在 host netns 中创建的普通、未打 mark 的 socket。LAN 侧本地 TCP 或 UDP
`:53` 监听对相应 transport 优先；通配监听只有在目的地址属于本机时才优先。关闭
`bind` 不会关闭透明 53 端口拦截。所有请求的 socket 会同步、all-or-nothing 地
bind：任一失败会关闭其他 socket 并令启动失败。监听器归进程所有，因此 SIGHUP 中
endpoint 语义变化会被拒绝并提示必须重启；endpoint 不变时继续使用新发布的 DNS
runtime。通配和 LAN bind 会暴露无认证的递归 resolver，必须用主机防火墙限制来源。

每个查询都取当前 `DnsServiceProvider` generation，因此与透明 DNS 共享
request/response routing、缓存、singleflight、上游连接池和路由投影。只转发完整的
单问题请求。UDP 应答将客户端 EDNS size 钳制到 `512..=1232`，且通配 socket 会保留
查询命中的本地地址作为应答源。透明与独立 TCP DNS 都支持 RFC 7766 双字节 framing 与持久连接，并将每次长度/
正文读取及应答写入限制在 30 秒内。独立 TCP 最多占用全局连接预算的四分之一。
独立查询没有拦截所得的原始目的地址：若 request routing 选择 `asis`，honk 会返回
DNS 失败，而不会递归拨回自己的监听器。

### 上游

| 字段 | 类型 | 默认值 | 含义 |
| ------ | ------ | -------- | ------ |
| `name` | string | 必填 | Id；dae 中冒号前的名字 |
| `address` | string | 必填 | `ip:port` 或主机；dae 中取 URI 的主机部分 |
| `protocol` | enum | `udp` | `udp`/`tcp`/`tls`/`https`/`quic`；dae 中由 URI scheme 决定（`udp://`、`tcp://`、`tcp+udp://`/`udp+tcp://`、`tls://`、`https://`、`h3://`、`quic://`，无 scheme 默认为 UDP） |
| `tls_server_name` | string? | null | DoT/DoH/DoQ/DoH3 SNI。dae 语法自动从主机名派生；IP 字面量上游需用 URI query 参数显式指定，如 `tls://1.1.1.1:853?tls_server_name=cloudflare-dns.com` |
| `outbound` | string? | null | 经节点/组发出；dae 中行内后缀 `'uri' -> <name>`（旧：`outbound: name`） |

**运行时说明：** UDP/TCP/DoT/DoH/DoQ/DoH3 均可用（连接复用）。DoT/DoH/TCP 支持 `-> proxy`（经节点/组的 TCP 隧道）；DoQ/DoH3 暂仅直连。UDP+代理由该上游策略刻意承载为 TCP-DNS；SOCKS5 RFC 1928 UDP 仍是独立的完整 transport。

### 路由 / 规则

| 字段 | 含义 |
| ------ | ------ |
| `request { <条件> [&& <条件>...] -> <动作> }` | 请求规则，首条命中。条件：`qname(suffix:/keyword:/full:/regex:/geosite:...)`、`qtype(a/aaaa/...)`；`!` 取反。动作：`reject`、`asis`（透明查询使用客户端原 transport 拨拦截所得原始目的地址，UDP TC 时改用 TCP 重试；独立查询返回 DNS 失败）或上游名 |
| `request { fallback: <上游名> }` | 无请求规则命中时的上游 |
| `response { <条件> [&& <条件>...] -> <动作> }` | 响应规则，首条命中。条件：`upstream(name)`、`qname(...)`、`ip(cidr, geoip:...)`；`!` 取反。动作：`accept`、`reject` 或上游名（重新查询，深度 ≤ 3） |
| `response { fallback: accept\|reject }` | 无响应规则命中时的判定 |
| `routing.rules[].domain` / `.upstream` | 旧版纯模式字段（前缀 `suffix:`/`keyword:`/`full:`/`regex:`）；无新式规则时在加载时转换为请求规则 |

### 策略

`preferipv4` | `preferipv6` | `ipv4only` | `ipv6only` | `both`

- `ipv4only` / `ipv6only`：另一地址族的查询在请求期直接回 NODATA，不转发上游。
- `preferipv4` / `preferipv6`：两个地址族都会转发；当偏好族对同名有应答时，另一族的应答被压制（NODATA）；偏好族无应答时返回另一族的真实应答（允许回退）。缓存未命中时偏好族检查需额外一次上游查询，并保留原查询除 QTYPE 外的完整 wire profile。
- `both`：`DnsConfig` 的实际默认值；并发转发符合资格的 A 与 AAAA，两个地址族都不压制。honk 配置省略 `ipversion_prefer` 时保持此默认值。

dae：`ipversion_prefer: 4` 映射 `preferipv4`，`6` 映射 `preferipv6`（其他值 = `preferipv4`）；only 模式无法通过 dae 语法表达。

### 缓存

| 字段 | 默认值 | 含义 |
| ------ | -------- | ------ |
| `enabled` | `true` | 开关。**dae：** `optimistic_cache` |
| `ttl` | `600` | 正缓存固定 TTL（覆盖应答 min TTL；`0` 表示沿用上游）。**dae：** `optimistic_cache_ttl` |
| `max_size` | `10000` | 最大条目，同时按每条 4 KiB 限制保留的 query/response wire 总字节（每分片至少 65,535 字节、全局最多 64 MiB）；`0` 仍接受，但会告警并钳制为 `1`。**dae：** `max_cache_size` |

可选持久化：`experimental { cache_file { ... } }` 的 `store_dns`。条目使用可回滚的
`dns:v2:` 命名空间，只有 expiry、wire identity、入口 profile、scope、operation 与
策略均匹配时才恢复。v2 命名空间冷启动且不改动旧行；旧版本忽略 v2 行，因此回滚时
可将其留在 `cache.db` 中而不改变行为。

缓存与 singleflight 共用资格判定。只有标准单问题 QUERY、answer/authority 计数为零、
最多一个无 option 的 EDNS-v0 OPT 才符合资格。RD/AD/CD、DO、精确 question wire、
UDP size、入口 profile、策略、scope 与 operation 均在 key 中保持隔离。多问题请求
会在策略规划前被拒绝；不受支持的 flags、EDNS option（包括 ECS/COOKIE）与 EDNS-v1
绕过这两项优化；取消会释放 flight。

运行时 cache 与 singleflight key 共享同一份不可变二进制 query identity；
operation 变体复用该分配，cache 分片使用预计算的运行时 hash。SQLite 文本编码
只存在于持久化边界。


### Runtime 与可观测性

重载一次切换包含 DNS 策略、Router、GroupManager 快照、transport manager、路由投影与
固定 outbound runtime 的完整 generation。lease 让旧请求继续使用匹配的节点/session
generation；这些 lease 与 DNS transport 退役后，旧 outbound pool 才拒绝新 open 并 drain
存活 stream。退役 deadline 与保留 generation 上限约束 DNS 关闭，transport 初始化/关闭
使用 singleflight 且幂等。

相互独立、单调递增的 counter 覆盖 hit/miss/stale、flight 饱和/取消/重试、
持久化丢弃/flush 失败、runtime 退役、transport 初始化/重置、投影失败/重试和
结果分类。记录不会等待 shared gate；内部 best-effort scrape 逐项读取，不提供
counter 之间的一致性。失败日志使用有界 `error_kind`：
forwarder 为 `engine`/`exchange`/`response`/`internal`/`rejected_plan`，持久化为
`worker_closed`/`ack_dropped`/`worker_failed`/`database`，投影为
`map_full`/`backend_write`，transport 为 `exchange_failed` 并带有界 transport label。
日志不记录 query name、upstream 地址或自由格式 error。`/stats` 仍是出站统计面；
runtime DNS 遥测不会新增公开 metric 或 API。

---

## 6. 订阅（`subscription { ... }`）

dae 语法中每个订阅一行：`tag: 'https://...'` 或裸 `'https://...'`（名称即 URL）。下表为订阅模型字段；`sub_type` / `update_interval` / `user_agent` / `headers` / `enabled` 均为结构化模型字段，dae 语法无对应键。

| 字段 | 类型 | 默认值 | 含义 |
| ------ | ------ | -------- | ------ |
| `id` | UUID | 随机 | Id |
| `name` | string | 必填 | 显示名；dae 中为冒号前的 tag |
| `url` | string | 必填 | 拉取 URL |
| `sub_type` | enum | `simple` | `simple`/`clash`/`sip008`/`custom` |
| `update_interval` | u64 | `86400` | 秒；`0` = 仅手动 |
| `user_agent` | string? | null | UA |
| `headers` | `{key,value}[]` | `[]` | 额外头 |
| `enabled` | bool | `true` | 是否启用 |
| `last_updated` | datetime? | null | 上次拉取 |
| `node_count` | u32 | `0` | 上次节点数 |
| `created_at` | datetime | now | 创建时间 |

节点仍只存在于运行时，不会写回配置文件。默认启用
`global { store_subscribe: true }`：每次成功获取并解析的原始正文会原子写入
`global.data_dir` 下的 `.sub`；已有旧 `./.sub` 会继续使用，直至手动迁移。目录权限为
`0700`、文件权限为 `0600`，文件名由 URL 与请求身份散列得到。启动时先恢复有效缓存，
再在后台联网刷新；已恢复的订阅不再占用 5 秒首次拉取等待时间。重载先沿用当前节点，
并为没有可沿用节点的已启用订阅读取缓存。拉取、解析或落盘失败时，当前节点与上一次
有效缓存均保持不变。

---

## 7. Experimental（`experimental { ... }`）

```dae
experimental {
    clash_api {
        external_controller: '0.0.0.0:9090'
        external_ui: yacd
        secret: ''
        default_mode: Rule
    }
    cache_file {
        enabled: false
        path: 'cache.db'
        cache_id: ''
        store_fakeip: false
        store_dns: false
    }
    udp_nfqueue {
        enabled: false
    }
}
```

### `experimental { udp_nfqueue { ... } }`

| 字段 | 默认值 | 含义 |
| ------ | -------- | ------ |
| `enabled` | `false` | 用 NFQUEUE 保留仍有歧义的 LAN 转发 UDP 首包，等待用户态终判 |

该字段修改后必须重启。设为 `true` 时，启动只接受带 `ebpf` feature 且使用真实 eBPF
后端的构建；`--mock-ebpf` 和不带 `ebpf` 的构建会被拒绝。该 hook 覆盖 LAN 转发流量，
因为主机 `inet prerouting` 位于 LAN TC 之后。本机发起的 WAN 出口流量仍走规范 TPROXY
路径。DNS 53、内部/特殊流量、`must`、`block`、反向流量和已经可以安全直连的决策
绝不入队；只暂存仍有歧义的用户态/域名决策。

机制固定为：raw-netlink 队列 `320`、一个 listener 向一个有界 ingest actor 投递，
不启用 bypass、fanout、fail-open，也没有用户可配置的队列/worker 策略。honk 独占
名称精确为 `inet honk_nfqueue` / `udp_decision` 的 nftables 对象；运行期间，同一网络
命名空间中的防火墙管理器不得修改它们。固定的 `UDP_DECISION_SEQUENCE` 分配器跨普通
重启/清理保留。其兼容回滚的 12 字节值在 `next` 中保存完整 raw token；启动只校验、
不改写，因此旧 binary 会从同一 token 边界继续。该 raw 值仍划分为两位 generation 与
28 位 sequence。sequence 耗尽时，honk 先 fence 新暂存，排空已保留报文与延期 token
cleanup 并硬重绑队列；只有候选 generation 及其到 generation 3 的所有更高 generation
都未出现在存活 token 绑定 map 中，才能切换。旧 allocator 回滚后只会沿该区间单调
递增。若没有满足条件的候选，暂存保持 fenced 且 supervisor 持续重试；无需暂存的 UDP
继续工作，新的歧义流 fail closed。无需重启操作系统。

被保留的 skb 位于 conntrack/NAT 之前。最终 direct 使用 token 校验的
Arm → 按 FIFO 以最终 mark accept → Activate，不创建用户态直连 socket、payload 副本、
故意重传、endpoint 或 connection 条目。Proxy 先提交 token 绑定状态，再把唯一的保留
payload 副本转交给规范 UDP 初始化器，丢弃原始 skb，最后只拨号/发送一次。Block/cancel
丢弃原始 skb。重载与关闭会 fence readiness，并在队列/表拆除前静默/取消所有 guard。
队列、listener 和 verdict 故障仍为致命错误；分配器耗尽按上述 fenced generation 轮换恢复。

### `experimental { clash_api { ... } }`

| 字段 | 默认值 | 含义 |
| ------ | -------- | ------ |
| `external_controller` | `""` | 监听地址；空 = 关闭 |
| `external_ui` | `""` | 静态 UI 目录；相对路径优先使用 `global.data_dir` 下的已有目录，再使用已有工作目录相对目录；不存在时指向 `global.data_dir` |
| `secret` | `""` | Bearer / `?token=`；空 = 无鉴权 |
| `default_mode` | `"Rule"` | `Rule` / `Global` / `Direct` |

### 已实现 HTTP API

| 方法 | 路径 | 用途 |
| ------ | ------ | ------ |
| GET | `/` `/version` | 问候 / 版本 |
| GET/PUT/PATCH | `/configs` | 模式等 |
| GET | `/proxies` | 节点 + 组 |
| GET/PUT | `/proxies/{name}` | 详情 / 设置 Selector |
| GET | `/proxies/{name}/delay` | 按需测速 |
| GET | `/group/{name}/delay` | 组测速 |
| GET | `/rules` | 每条规则一行：简单 matcher 使用原生 Clash 类型；组合、取反或 `must` dae 规则使用 `complex` 并保留完整语句 |
| GET/DELETE | `/connections` | 列表 / 关闭全部 |
| DELETE | `/connections/{id}` | 关闭单个 |
| GET | `/traffic` | WS 或分块 JSON 行 |
| GET | `/stats` | 出站与稳定 UDP 统计 |
| GET | `/logs` | WS 或分块 |
| GET | `/dns/query` | DoH 风格 JSON |
| POST | `/cache/fakeip/flush` | FakeIP 前缀清理 |
| POST | `/cache/dns/flush` | DNS 缓存清理 |
| GET | `/providers/proxies` | 组作为 provider |
| GET | `/providers/rules` | 空桩 |
| GET | `/ui` … | 外部 UI |

### `GET /stats` UDP schema

`udp` 是 `GET /stats` 中稳定的嵌套对象。下文的点记法 `/stats.udp` 表示该
嵌套对象，**不是**独立路由。列出的键始终存在；尚未发生对应事件时计数可为零。
报文路径不会创建动态 node/tag label。

```text
udp = {
  endpoint: { hits, misses },
  latency: {
    route: H, dial: H, replyReady: H, firstSend: H, firstReply: H
  },
  capacity: { rejected },
  slowPermit: { accepted, rejected, closed },
  queue: { accepted, full, closed },
  firstSend: { failures },
  stagger: { attempts, winners, cancellations },
  warm: { attempts, successes, failures },
  nfqueue: {
    received, activeFlows, kernelQueueDepth, kernelStatsAvailable,
    kernelStatsReadErrors, kernelDropped, kernelUserDropped, heldPackets,
    heldPeak, socketReceiveBufferBytes, actorQueueFull, correlatorFull,
    actorQueueDepth, actorQueuedBytes, actorOldestAgeNanos, directAccepted,
    proxyCopied, proxyDropped, block, cancel, drop, tokenMismatch,
    tokenExhaustion, tokenRollovers, verdictErrors, receiptToVerdict: H
  }
}
H = { count, sumNanos, buckets }  // buckets 有固定 64 个 log2 slot
```

`queue` 是 endpoint driver 队列，与记录 slow-path admission 的
`slowPermit` 不同。stagger counter 只用于 cold URLTest preparation。AnyTLS
candidate 使用计入 pool cap 的 caller-owned provisional session slot，QUIC
candidate 使用 detached client。loser 取消会关闭对应 detached work；winner 在
endpoint publication 前完成 promotion/arbitration。若普通流量已先填充 QUIC
generation slot，则保留该 incumbent，winner transport 只为当前选中流持有自己的
connection。warm 的 `successes` 只计 `Ready`；`NotApplicable` 保持中性。

`nfqueue.received` 统计 listener 投递；`activeFlows` 是当前 pending correlator gauge。
独立于报文 dispatch 的一秒任务采样自有内核队列。`kernelStatsAvailable` 表示最近一次
读取是否成功；`kernelStatsReadErrors` 是累计失败数。读取失败时仍保留最近的
`kernelQueueDepth`、`kernelDropped` 和 `kernelUserDropped`，不会用含义不明的零值覆盖；
本地 `heldPackets`、`heldPeak` 和 `socketReceiveBufferBytes` gauge 仍继续刷新。
`kernelDropped` 与 `kernelUserDropped` 是跨队列硬重绑累加的进程生命周期 counter，
`kernelQueueDepth` 则是当前队列实例的 gauge。`heldPackets` 与 `heldPeak` 统计已投递的
verdict guard；`socketReceiveBufferBytes` 是 netlink 实际接收缓冲区大小。
`actorQueueFull` 统计 ingest actor 的 fail-closed admission 丢包；`correlatorFull`
统计达到 4,096 个并发 flow cell 或单流 64 个保留 verdict 硬上限时的丢包。
`actorQueueDepth`、`actorQueuedBytes` 和 `actorOldestAgeNanos` 暴露当前 ingest 压力。
`directAccepted`、`proxyDropped`、`block`、`cancel` 和 `drop` 统计成功内核 verdict；
`proxyCopied` 统计唯一 payload
所有权转交。`tokenMismatch`、`tokenExhaustion`、`tokenRollovers` 和 `verdictErrors`
暴露 token/verdict 事件。`receiptToVerdict` 测量 listener 收包到成功 verdict 的时间；
NFQA timestamp 不保证存在，因此不表示内核队列驻留时间。

`/stats` 另有顶层 `warm` 对象，为即时 gauge：

```text
warm = {
  nodes: { preconnect, health, udp, selector, traffic },
  sessions: { anytls, vless, tuic, juicity, hysteria2 }
}
```

`nodes` 按保留热资源的原因统计当前热节点（一个节点可同时计入多个原因；
无记录原因的热节点计为 `traffic`）；`selector` 表示始终启用的 Selector
当前叶节点常驻。`sessions` 按协议统计驻留的 AnyTLS/VLESS 池 session 与已占用的
QUIC client 槽。gauge 跟随当前 generation：资源排干后节点在下一个快照中消失。

环境变量：`HONK_UI_DOWNLOAD_URL` 覆盖 UI zip。

### `experimental { cache_file { ... } }`

| 字段 | 默认值 | 含义 |
| ------ | -------- | ------ |
| `enabled` | `false` | 持久化 SQLite 缓存 |
| `path` | `"cache.db"` | 数据库路径；相对路径优先使用 `global.data_dir`，再使用原配置目录下已有路径 |
| `cache_id` | `""` | 命名空间 id |
| `store_fakeip` | `false` | FakeIP 持久化意图（引擎未完成） |
| `store_dns` | `false` | 持久化 DNS 应答 |

启用后会持久化 Selector 选择与 Clash 模式。

---

## 8. CLI（`honk-core`）

| 参数 | 默认值 | 含义 |
| ------ | -------- | ------ |
| `-c` / `--config` | `/etc/honk/config.dae` | 配置路径 |
| `-b` / `--bpf-object` | 内嵌 | 外部 eBPF 目标文件 |
| `--bpf-pin-root` | `/sys/fs/bpf` | pin 根目录 |
| `-d` / `--debug` | 关 | Debug 日志 |
| `--mock-ebpf` | 关 | 不使用内核 eBPF |

日志级别顺序：`--debug` → `RUST_LOG` → `global { ... }` 的 `log_level` → `info`。

### 子命令

```bash
honk-core mode <rule|global|direct>
honk-core proxy <group> <node>
honk-core delay <node> [--url HOST:PORT]
```

---

## 9. eBPF / 运行时旋钮（不全在配置文件）

| 项 | 位置 | 说明 |
| ---- | ------ | ------ |
| 内嵌目标文件 | 构建 `ebpf` feature | `build.rs` + `include_bytes!` |
| 外部目标文件 | `--bpf-object` | 覆盖内嵌 |
| Pin 根 | `--bpf-pin-root` | 默认 `/sys/fs/bpf` |
| Bypass mark | 代码 `0x100` | 拨号/探测/DNS 上游 |
| tproxy mark | `global` 的 `tproxy_mark` | 策略 / 历史兼容 |
| Geo 文件 | 运行时路径 | `geoip.dat` / `geosite.dat` |
| UI 下载 URL | `HONK_UI_DOWNLOAD_URL` | Clash 外部 UI |

---

## 10. 健康检查组件行为

由 **global** + 可选 **每组覆盖** 配置，实现为 `AliveDialerSet`：

| 行为 | 细节 |
| ------ | ------ |
| 域 | Tcp、DnsUdp、DataUdp × v4/v6 |
| TCP 探测 | 对 `tcp_check_url` 发 HTTP，或裸连接 |
| UDP 探测 | 经节点 `dial_udp_transport` 向 `udp_check_dns` 发 DNS |
| 按组 check URL | 配了 `check_url` 的组按其目标探测成员（子组成员经其当前选中节点探测，结果记到子组 tag,与 sing-box RealTag 一致）；(tag, url) 状态与全局独立——对该 URL 死亡只把该成员排除出该组 |
| 并发 | 默认批次 10 |
| 恢复 | 连续 2 次成功；相关网卡、地址或路由变化会清除旧退避，并让下一次成功探测直接验证恢复 |
| 死亡节点重试 | 每 `min(5s, check_interval)` 重新检查退避已到期的死亡 TCP/UDP 协议族；实际探测仍遵循 5s→300s 指数退避 |
| 深度退避 | 连续失败 10 次后仍以 max_cooldown（300s）慢速节奏继续探测，不永久停止 |
| 拨号失败 | 清除延迟历史并注入一个 10s 合成罚样本（sing-box `DeleteURLTestHistory` + 防抖动）；节点 alive→dead 翻转时清除其连接池条目并回收 UDP endpoint |
| UDP driver 失败 | transport 发送、接收或回包空闲超时会上报 DataUdp 流量失败；主动 endpoint 退役和进程关闭不影响健康状态 |
| 延迟持久化 | 每节点最近真实延迟样本写入 cache.db（60s 周期），启动时恢复，超过 24h 丢弃 |
| 新节点宽限 | 约 60s |
| URLTest 空闲 | `idle_timeout` 停止未使用组的探测 |
| eBPF 推送 | 已死出站不再被 redirect |

UDP 选择排除：两个 UDP 域都明确死亡 → 即使 TCP 存活也不选入 UDP；从未 UDP 探测过则继承 TCP 存活性。

---

## 11. 相关文档

- [设计文档](./design.zh.md)
- [配置说明](./configuration.zh.md)
- [DNS 灰度与回滚操作手册](./dns-rollout.zh.md)
- 示例：`config.dae`、`config.min.dae`
