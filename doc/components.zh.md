# honk 组件详细配置参考

各主要组件的字段级说明，配合 [configuration.zh.md](./configuration.zh.md) 使用。

配置文件使用 **dae 语法**（`global { ... }`、`node { ... }`、`group { ... }`、`routing { ... }`、`dns { ... }`、`subscription { ... }`、`experimental { ... }` 各节），完整示例见仓库根目录的 `config.dae` 与 `config.min.dae`。

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
| `lan_interface` | string[] | `[]` | 拦截的 LAN 网卡；空 = 不拦截；逗号分隔 |
| `wan_interface` | string[] | `[]` | WAN 网卡；dae 允许 `auto`；逗号分隔 |
| `auto_config_kernel_parameter` | bool | `false` | 自动 sysctl（需 root） |
| `tcp_check_url` | string[] | Cloudflare HTTP + 1.1.1.1 + IPv6 | TCP 健康检查目标；逗号分隔 |
| `tcp_check_http_method` | string | `"HEAD"` | URL 检查的 HTTP 方法 |
| `udp_check_dns` | string[] | dns.google / 8.8.8.8 / IPv6 | UDP 健康检查 DNS 目标；逗号分隔 |
| `check_interval_secs` | u64 | `30` | 检查间隔（秒）。**dae：** `check_interval` 时长（如 `300s`） |
| `check_tolerance_ms` | u64 | `50` | URLTest 切换阈值（ms）。**dae：** `check_tolerance`（如 `30ms`） |
| `dial_mode` | string | `"domain"` | `ip` / `domain` / `domain+` / `domain++` |
| `lan_tcp_mss` | u16 | `0` | 已弃用；仅解析兼容 |
| `allow_insecure` | bool | `false` | 全局 TLS 跳过校验回退 |
| `sniffing_timeout_ms` | u64 | `30` | 嗅探超时（ms）。**dae：** `sniffing_timeout` 时长 |
| `tls_implementation` | string | `"tls"` | TLS 栈名称 |
| `utls_imitate` | string | `"chrome_auto"` | 预留（REALITY/uTLS 已延期） |
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
| `preconnect_node_count` | usize | `0` | 预连接数；`0` = 自动 `min(nodes,8)`（结构化模型字段，dae 语法无对应键） |

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
| `id` | UUID | 随机 | 稳定 id |
| `name` | string | **必填** | 路由 / API 名称；dae 中为链接前的 tag |
| `protocol` | enum | `ss` | 见协议表；dae 中由链接 scheme 决定 |
| `address` | string | 必填* | 主机或 `host:port` |
| `host` | string | `""` | 显式主机；否则从 `address` 取 |
| `port` | u16 | `0` | 服务端口 |
| `username` / `password` | string? | null | 认证 / UUID / 密钥；链接 userinfo |
| `encryption` | string? | null | SS/SSR/VMess 加密 |
| `plugin` / `plugin_opts` | string? | null | 插件名/参数；链接 `plugin` / `plugin-opts` |
| `transport` | string | `"tcp"` | `tcp` / `ws` / `grpc` / …；链接 `type`（或 `network`）参数 |
| `tls` | bool | `false` | 启用 TLS；trojan/vless/anytls 等链接自动开启 |
| `sni` | string? | null | TLS SNI；链接 `sni`（或未被传输占用的 `host`）参数 |
| `skip_cert_verify` | bool | `false` | 跳过证书校验；链接 `allowInsecure` / `insecure` 参数 |
| `network` | string? | null | V2Ray 风格 network 提示 |
| `ws_path` / `ws_host` | string? | null | WebSocket；链接 `path` / `host` 参数 |
| `grpc_service` | string? | null | gRPC service 名；链接 `serviceName` 参数 |
| `hy2_auth` / `hy2_obfs` | string? | null | Hysteria2 |
| `tuic_uuid` / `tuic_password` / `tuic_congestion` | string? | null | TUIC |
| `juicity_uuid` / `juicity_password` | string? | null | Juicity |
| `anytls_password` | string? | null | AnyTLS 密钥（等于链接密码） |
| `anytls_min_idle_session` | usize? | null | 池最小空闲会话；链接 `min_idle_session` |
| `anytls_idle_session_check_interval` | u64? | null | 空闲检查周期（秒）；链接 `idle_session_check_interval` |
| `anytls_idle_session_timeout` | u64? | null | 空闲驱逐（秒）；链接 `idle_session_timeout` |
| `mux` | bool | `false` | h2mux 多路复用（结构化模型字段，分享链接 / dae 语法无对应参数） |
| `mark` | u32? | null | 出站 SO_MARK（结构化模型字段，dae 语法无对应键） |
| `tags` | string[] | `[]` | 标签（结构化模型字段，dae 语法无对应键） |
| `subscription_id` / `group_id` | UUID? | null | 归属元数据（运行时填充） |
| `created_at` / `updated_at` | datetime | now | 元数据（运行时填充） |

\* 校验要求：`name` 非空，且 `address` 或 `host` 非空。

### 协议

| 取值 | 别名 | TCP | UDP | 说明 |
| ------ | ------ | ----- | ----- | ------ |
| `ss` | `shadowsocks` | 是 | 是 | AEAD + `2022-blake3-*` |
| `ssr` | `shadowsocksr` | 是 | 否 | `origin` + 有限 obfs；高级 proto 部分实现 |
| `trojan` | | 是 | 是 | TLS；经 transport 支持 WS/gRPC/h2mux |
| `trojan-go` | | 是 | 否 | 自有 mux 路径 |
| `vmess` | | 是 | 否 | AEAD；WS/gRPC/h2mux |
| `vless` | | 是 | 否 | 头里的 UDP 仅测试存在 |
| `socks5` | | 是 | 是 | UDP ASSOCIATE |
| `http` | | 是* | — | 走类似 direct 的拨号 |
| `hysteria2` | | 是 | 是 | 真实 QUIC/H3；salamander；BBR（无 brutal） |
| `tuic` | | 是 | 是 | TUIC v5 / quinn |
| `juicity` | | 是 | 是 | quinn 双向流 UDP |
| `anytls` | | 是 | 是 | 会话池 + UoT v2 |

内置 **`direct`** 节点在加载时注入（配置中可不写）。

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

注意：`mux`（h2mux）没有对应的分享链接参数，dae 语法下无法开启。

**AnyTLS 池**

```
node {
    my_anytls: 'anytls://secret@example.com:443?sni=example.com&min_idle_session=3&idle_session_check_interval=30&idle_session_timeout=30#my_anytls'
}
```

**Hysteria2 / TUIC / Juicity**

使用分享链接（`hysteria2://` / `tuic://` / `juicity://`），链接解析后填充 `hy2_*` / `tuic_*` / `juicity_*` 字段。QUIC ALPN/拥塞控制跟随 Handler 默认（Hy2 使用 BBR）。

### 分享链接 scheme

| Scheme | 说明 |
| -------- | ------ |
| `ss://` | SIP002 |
| `ssr://` | base64 参数 blob |
| `vmess://` | base64 JSON（v2rayN） |
| `vless://` / `trojan://` / `trojan-go://` | query 传 transport/TLS |
| `anytls://` | query 中的池参数 |
| `hysteria2://` / `tuic://` / `juicity://` | QUIC 族 |
| `socks5://` / `http://` / `https://` | 简单代理 |

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
| `filters` | string[] | `[]` | `name(...)` / `group(...)`；dae 中每条一个 `filter:` 行 |
| `groups` | string[] | `[]` | 嵌套组标签；`filter: group('a', 'b')`，也接受 `'a\|b'` / `'a, b'` |
| `default` | string? | null | Selector 默认节点名 |
| `final_outbound` | string? | null | 全死时出站。**dae：** `final` |
| `check_url` | string? | null | 覆盖全局 TCP 检查 URL（结构化模型字段，dae 语法无对应键） |
| `check_interval` | u64? | null | 覆盖间隔（秒）（结构化模型字段，dae 语法无对应键） |
| `tolerance` | u64 | `50` | URLTest 滞后（ms）；`0` = 任一更优即切（结构化模型字段，dae 语法无对应键；dae 用全局 `check_tolerance`） |
| `idle_timeout` | u64? | null | 空闲后停止检查（秒）；0/None = 永不（结构化模型字段，dae 语法无对应键） |
| `interrupt_connections` | bool | `false` | 选择变化时打断连接（结构化模型字段，dae 语法无对应键） |
| `created_at` | datetime | now | 元数据 |

### 策略

| 规范名 | 别名 | 行为 |
| -------- | ------ | ------ |
| `selector` | `select`、`fixed`、`fixed(0)` | 手动固定；API + cache |
| `urltest` | `min_moving_avg`、`min_avg10`、`min_last_delay` | 最低延迟 + tolerance；**TCP/UDP 分离** |
| `loadbalance` | `roundrobin`、`round_robin`、`balance` | 组内对存活成员轮询 |
| `fallback` | | 第一个存活粘性；无立即 failback |

### 过滤解析

1. `group('tag')` → 嵌套标签（`groups`），不进节点列表。
2. `name(...)` 过滤以 OR 方式匹配成员。
3. 无 filters 且无嵌套组 → **全部节点**。
4. 仅有嵌套组 → **不是**全部节点。

### 嵌套组

深度上限 8；构图时切断环并告警。拨号始终落到单个**叶子**节点。Clash 的 `all` 显示成员标签；健康检查展开叶子。

---

## 4. 路由（`routing { ... }`）

dae 语法中每条规则一行：`条件函数 && 条件函数 -> 出站`，以 `fallback:` 收尾：

```
routing {
    domain(suffix: google.com) -> proxy
    dip(geoip: cn) -> direct(must)
    fallback: direct
}
```

| 字段 | 类型 | 默认值 | 含义 |
|------|------|--------|------|
| `rules` | rule[] | `[]` | 有序规则；dae 中按书写顺序 |
| `default_outbound` | string | `"direct"` | 回退。**dae：** `fallback:` / `default:` |

### 规则字段

| 字段 | 类型 | 默认值 | 含义 |
| ------ | ------ | -------- | ------ |
| `name` | string | `""` | 显示名（dae 自动 `rule-N`） |
| 条件字段 | 扁平 | | 见下表 |
| `outbound` | string / complex | 必填 | 目标；dae 中 `->` 后为简单出站名 |
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

`domain` 参数标签：裸值/`suffix:` → 后缀；`keyword:`；`full:`；`regex:`；`geosite:`（`@` → `-`）。

### 复杂出站（仅结构化模型）

dae 语法的 `->` 目标只接受简单出站名（节点 / 组标签）。结构化模型中保留了 `or` / `and` / `balancer` / `chain` 复合出站 schema，但 **balancer/chain 未像简单字符串出站那样完整接通**。优先使用组策略。

---

## 5. DNS（`dns { ... }`）

```
dns {
    ipversion_prefer: 4
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
| `upstream` | list | 一个 `default` @ 223.5.5.5 UDP | 服务器；dae：`upstream { name: 'uri' }` |
| `routing` | object | fallback 默认 | 请求路由；dae：`routing { request { ... } }` |
| `strategy` | enum | `preferipv4` | 地址族策略；dae：`ipversion_prefer: 4\|6` |
| `cache` | object | 启用 | 缓存；dae：`optimistic_cache` / `optimistic_cache_ttl` / `max_cache_size` |

### 上游

| 字段 | 类型 | 默认值 | 含义 |
| ------ | ------ | -------- | ------ |
| `name` | string | 必填 | Id；dae 中冒号前的名字 |
| `address` | string | 必填 | `ip:port` 或主机；dae 中取 URI 的主机部分 |
| `protocol` | enum | `udp` | `udp`/`tcp`/`tls`/`https`/`quic`；dae 中由 URI scheme 决定（`udp://`、`tcp://`、`tcp+udp://`/`udp+tcp://`、`tls://`、`https://`、`h3://`、`quic://`，无 scheme 默认为 UDP） |
| `tls_server_name` | string? | null | DoT/DoH SNI；dae 语法中当主机名不是 IP 时自动派生 |
| `outbound` | string? | null | 经节点/组发出；dae 中行内后缀 `'uri' -> <name>`（旧：`outbound: name`） |

**运行时说明：** UDP/TCP/DoT/DoH/DoQ/DoH3 均可用（连接复用）。DoT/DoH/TCP 支持 `-> proxy`（经节点/组的 TCP 隧道）；DoQ/DoH3 暂仅直连。经代理的 DNS SOCKS5 UDP 路径不完整（UDP+代理隧道化为 TCP DNS）。

### 路由 / 规则

| 字段 | 含义 |
| ------ | ------ |
| `request { <条件> [&& <条件>...] -> <动作> }` | 请求规则，首条命中。条件：`qname(suffix:/keyword:/full:/regex:/geosite:...)`、`qtype(a/aaaa/...)`；`!` 取反。动作：`reject`、`asis`（拨查询的原始目的地址）或上游名 |
| `request { fallback: <上游名> }` | 无请求规则命中时的上游 |
| `response { <条件> [&& <条件>...] -> <动作> }` | 响应规则，首条命中。条件：`upstream(name)`、`qname(...)`、`ip(cidr, geoip:...)`；`!` 取反。动作：`accept`、`reject` 或上游名（重新查询，深度 ≤ 3） |
| `response { fallback: accept\|reject }` | 无响应规则命中时的判定 |
| `routing.rules[].domain` / `.upstream` | 旧版纯模式字段（前缀 `suffix:`/`keyword:`/`full:`/`regex:`）；无新式规则时在加载时转换为请求规则 |

### 策略

`preferipv4` | `preferipv6` | `ipv4only` | `ipv6only` | `both`

- `ipv4only` / `ipv6only`：另一地址族的查询在请求期直接回 NODATA，不转发上游。
- `preferipv4` / `preferipv6`：两个地址族都会转发；当偏好族对同名有应答时，另一族的应答被压制（NODATA）；偏好族无应答时返回另一族的真实应答（允许回退）。缓存未命中时偏好族检查需额外一次上游查询。
- `both`：不过滤。

dae：`ipversion_prefer: 4` 映射 `preferipv4`，`6` 映射 `preferipv6`（其他值 = `preferipv4`）；only 模式无法通过 dae 语法表达。

### 缓存

| 字段 | 默认值 | 含义 |
| ------ | -------- | ------ |
| `enabled` | `true` | 开关。**dae：** `optimistic_cache` |
| `ttl` | `600` | 正缓存固定 TTL（覆盖应答 min TTL；`0` 表示沿用上游）。**dae：** `optimistic_cache_ttl` |
| `max_size` | `10000` | 最大条目（必须 > 0）。**dae：** `max_cache_size` |

可选持久化：`experimental { cache_file { ... } }` 的 `store_dns`。

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

节点仅存内存；周期刷新经控制面合并。

---

## 7. Experimental（`experimental { ... }`）

### `experimental { clash_api { ... } }`

| 字段 | 默认值 | 含义 |
| ------ | -------- | ------ |
| `external_controller` | `""` | 监听地址；空 = 关闭 |
| `external_ui` | `""` | 静态 UI 目录 |
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
| GET | `/rules` | 规则 |
| GET/DELETE | `/connections` | 列表 / 关闭全部 |
| DELETE | `/connections/{id}` | 关闭单个 |
| GET | `/traffic` | WS 或分块 JSON 行 |
| GET | `/stats` | 出站统计 |
| GET | `/logs` | WS 或分块 |
| GET | `/dns/query` | DoH 风格 JSON |
| POST | `/cache/fakeip/flush` | FakeIP 前缀清理 |
| POST | `/cache/dns/flush` | DNS 缓存清理 |
| GET | `/providers/proxies` | 组作为 provider |
| GET | `/providers/rules` | 空桩 |
| GET | `/ui` … | 外部 UI |

环境变量：`HONK_UI_DOWNLOAD_URL` 覆盖 UI zip。

### `experimental { cache_file { ... } }`

| 字段 | 默认值 | 含义 |
| ------ | -------- | ------ |
| `enabled` | `false` | 持久化 SQLite 缓存 |
| `path` | `"cache.db"` | 数据库路径 |
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
| UDP 探测 | 经节点 `dial_udp` 向 `udp_check_dns` 发 DNS |
| 并发 | 默认批次 10 |
| 恢复 | 连续 2 次成功 |
| 新节点宽限 | 约 60s |
| URLTest 空闲 | `idle_timeout` 停止未使用组的探测 |
| eBPF 推送 | 已死出站不再被 redirect |

UDP 选择排除：两个 UDP 域都明确死亡 → 即使 TCP 存活也不选入 UDP；从未 UDP 探测过则继承 TCP 存活性。

---

## 11. 相关文档

- [设计文档](./design.zh.md)
- [配置说明](./configuration.zh.md)
- 示例：`config.dae`、`config.min.dae`
