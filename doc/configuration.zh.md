# honk 配置说明

本文说明如何配置 **honk**：配置格式、顶层分段与常用示例。

逐字段的组件级说明（节点/组/DNS/CLI 全表）见 [components.zh.md](./components.zh.md)。

## 1. 配置格式

honk 使用原始的 **dae 配置语法**（`{ section { ... } }`）作为配置格式，配置文件通常以 `.dae` 结尾。语法要点：

- 顶层由若干 `section { ... }` 组成（包括 `include { ... }`）；`#` 为行注释。
- 除 `include` 外，键值对写作 `key: value`；含特殊字符的值用引号包裹（单双引号均可，如 `tcp_check_url: 'http://cp.cloudflare.com,1.1.1.1'`）。
- 列表值用逗号分隔写在同一行（如 `lan_interface: eth0, eth1`）。

仓库内示例：

- `config.dae`（完整功能示例）
- `config.min.dae`（最小示例）

### 拆分配置文件

顶层 `include` 分段可把多个 `.dae` 文件合并为一份配置：

```dae
include {
    config.d/*.dae
    '/etc/honk/config.d/extra config.dae'
}
```

- 条目可裸写或加引号，并支持 `*`、`?`、`[]` glob；同一模式的匹配按字典序加载。未匹配项、目录和非 `.dae` 文件会跳过。
- 相对路径始终相对于传给 `--config` 的入口配置所在目录，即使该语句出现在嵌套 include 中也是如此。绝对路径仅可位于入口目录树内，符号链接的实际目标同样会检查。
- 先合并入口文件的各分段，再依次合并每个被包含文件及其子文件。后面的标量覆盖前面的值；节点、组、DNS 上游与路由规则按此顺序追加。
- 同一文件被重复包含（包括循环）会报错。

## 2. 顶层结构

```text
include { ... }      # 合并其他 .dae 配置文件
global         # 透明代理、健康检查、拨号模式
node           # 代理节点（分享链接）
group          # 节点/嵌套组的选择策略
routing        # 有序流量规则 + fallback
dns            # 上游、DNS 路由、缓存
subscription   # 远程节点列表
experimental   # clash_api、cache_file
```

内置：

- 出站 **`direct`** 和 **`block`** 在加载时自动注入（保留协议节点，可用于组过滤与路由）；用户节点不得占用其名称或协议。
- **`block`** 丢弃流量。

## 3. 最小示例

```dae
global {
    wan_interface: auto
    lan_interface: eth0
    log_level: info
    dial_mode: domain
    auto_config_kernel_parameter: true
    tcp_check_url: 'http://cp.cloudflare.com,1.1.1.1'
    check_interval: 30s
    check_tolerance: 50ms
    bootstrap_resolver: '223.5.5.5:53'
}

node {
    trojan-node: 'trojan://password@trojan.example.com:443?sni=trojan.example.com'
}

group {
    proxy {
        filter: name(keyword: 'node')
        policy: min_moving_avg
    }
}

routing {
    dip(geoip: private) -> direct
    domain(suffix: google.com, suffix: youtube.com) -> proxy
    fallback: direct
}
```

## 4. 完整示例

```dae
global {
    tproxy_port: 12345
    log_level: info
    lan_interface: eth0
    wan_interface: auto
    auto_config_kernel_parameter: true
    tcp_check_url: 'http://cp.cloudflare.com'
    check_interval: 30s
    check_tolerance: 50ms
    dial_mode: domain
    bootstrap_resolver: '223.5.5.5:53'
}

node {
    trojan-node: 'trojan://trojan-password@trojan.example.com:443?sni=trojan.example.com'
}

group {
    proxy {
        filter: name(keyword: 'node')
        policy: min_moving_avg
    }
}

routing {
    dip(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8) -> direct
    domain(suffix: google.com, suffix: youtube.com, suffix: github.com) -> proxy
    fallback: direct
}

dns {
    ipversion_prefer: 4
    optimistic_cache: true
    optimistic_cache_ttl: 600
    max_cache_size: 10000
    upstream {
        alidns: 'udp://223.5.5.5:53'
    }
    routing {
        request {
            fallback: alidns
        }
    }
}

experimental {
    clash_api {
        external_controller: '127.0.0.1:9090'
        secret: 'change-me'
        default_mode: 'Rule'
    }
    cache_file {
        enabled: true
        path: 'cache.db'
        store_dns: true
    }
}
```

## 5. Global 要点

| 主题 | 关键字段 | 建议 |
| ------ | ---------- | ------ |
| 拦截网卡 | `lan_interface`、`wan_interface` | 省略 LAN 时不安装任何 LAN hook；已配置的 WAN hook 仍代理本机发起的 TCP/UDP。`auto` 解析默认路由网卡 |
| 监听 | `tproxy_port` | 默认 `12345`；`tproxy_mark`（默认 `0x08000000`）在 dae 语法中不可设置 |
| 内核 | `auto_config_kernel_parameter` | 需 root；自动设置有用的 sysctl |
| 健康检查 | `tcp_check_url`、`udp_check_dns`、`check_interval`、`check_tolerance` | 驱动 AliveDialerSet / URLTest；时长写作 `30s` / `50ms` |
| 拨号 | `dial_mode` | `ip` / `domain` / `domain+` / `domain++` |
| 解析 | `bootstrap_resolver`、`fallback_resolver` | 解析节点域名时避免自拦截死锁 |
| 超时 | `connect_timeout_ms`、`dns_resolve_timeout_ms`、`relay_idle_timeout_secs` | dae 语法暂不解析这些字段，使用内置默认值 |

**仅代理本机流量：** 主机没有需要拦截的下游 LAN 流量时，省略 `lan_interface`：

```dae
global {
    wan_interface: ens3
    dial_mode: ip
}
```

此模式只安装 WAN ingress/egress hook。本机创建并经 `ens3` 发出的 TCP/UDP 会进入 honk；转发的 LAN 流量和 loopback 流量不受影响。不要把 `lo` 当作虚拟 LAN 接口加入配置。


**拨号模式：**

| 取值 | 适用场景 |
| ------ | ---------- |
| `ip` | 简单 IP 路由；不嗅探 |
| `domain` | 默认；嗅探并校验目的 IP |
| `domain+` | DNS 不经过 honk 时 |
| `domain++` | 强制嗅探并按 SNI/Host 重路由 |

### 预热与拨号预算

honk 有三套互相独立的预热机制，全部有预算约束——都不随节点数量膨胀，
大订阅可放心使用：

| 机制 | 配置项 | 默认 | 说明 |
| ------ | -------- | ------ | ------ |
| 启动裸 TCP 预连接 | `preconnect_node_count` | `'auto'` | `'auto'` = 最多 8 个节点（各组当前选中优先，其次配置顺序）;`0` 关闭；`N` 指定数量。仅可裸 TCP 池化的协议参与——AnyTLS/QUIC 与内置 `direct`/`block` 一律跳过。 |
| TCP/TLS 保活集合 | `tcp_warm_node_count` | `1` | 每组每 IP 族保活最快的 K 个 AnyTLS/TCP 叶子。节点少（<50）时设 `3`-`5` 可明显降低非 winner 链路的首连延迟；大订阅保持 `1`-`2`。 |
| UDP 预热集合 | `udp_warm_node_count` | `0` | 每组每 IP 族 top-N 个 UDP 叶子；进程级总量自动封顶为 `4×N`，组再多也不会失控。 |
| 并发拨号上限 | `max_concurrent_dials` | `64` | 按 generation 限制并发代理拨号（connect + 协议握手）；内置 `direct`/`block` 本地拨号不占额度。reload 会更新 replacement 的局部上限，但新旧 generation 始终共享启动时确定的同一个描述符 gate。 |

健康探测只测不暖：冷节点被探测后不会留下任何常驻会话，400 节点的
订阅也不会因健康检查常驻 400 条隧道。`/stats` 的 `warm` 字段可观测
当前预热清单（来源 × 热节点数、每协议驻留会话数）。

## 6. 节点与分享链接

节点在 `node { }` 中以**分享链接**声明，格式为 `tag: 'scheme://...'`（tag 即节点名），也接受不带 tag 的裸链接。单引号、双引号均可；解析失败的条目会在 stderr 打警告并跳过。

解析支持的 scheme：`ss://`、`socks5://`、`trojan://`、`vmess://`、`vless://`、`hysteria2://`、`tuic://`、`juicity://`、`anytls://`。

分享链接中的参数会映射到 `Node` 字段：`name`、`protocol`、`address`/`host`、`port`、`password`/`username`、`encryption`、`tls`、`sni`、`transport`、`ws_path`、`ws_host`、`grpc_service`，以及 Hy2/TUIC/Juicity/AnyTLS 专用字段。

完整字段表与协议注意点（含 UDP 支持矩阵）见 [components.zh.md](./components.zh.md)。

## 7. 组（group）

```dae
group {
    proxy {
        filter: name(keyword: 'HK')
        filter: name('us1')
        filter: group('hk', 'jp')   # 嵌套子组（可选）
        policy: min_moving_avg      # fixed(0) | min_moving_avg | roundrobin | fallback
        default: 'us1'              # selector 默认节点
        final: direct               # 成员全死时的出站
    }
}
```

组级 `tolerance`、`idle_timeout`、`interrupt_connections` 在 dae 语法中不可设置：URLTest 切换滞后由全局 `check_tolerance`（如 `check_tolerance: 50ms`）控制，其余使用内置默认值。

**过滤表达式：**

| 表达式 | 含义 |
| -------- | ------ |
| `name('exact')` | 精确名称 |
| `name(keyword: 'pat')` | 子串匹配 |
| `group('hk')` / `group('hk', 'jp')` | 嵌套子组 |

经验规则：

- **无** filters 且 **无** 嵌套组 → 包含**全部**节点。
- 仅有嵌套组 → **不会**自动吞入全部节点。
- 多个 `filter: name(...)` 行之间是 OR。

**策略：**

| 策略 | dae 写法 | 行为 |
| ------ | ---------- | ------ |
| `selector` | `fixed(0)`、`select` | 手动固定 |
| `urltest` | `min_moving_avg`、`min_avg10`、`min_last_delay` | 最低延迟 + tolerance；TCP/UDP 分离 |
| `loadbalance` | `roundrobin`、`round_robin`、`balance` | 存活成员轮询 |
| `fallback` | `fallback` | 声明顺序第一个存活；粘性 |

## 8. 路由（routing）

规则有序，按源码书写顺序匹配（靠前优先），以 `fallback:` 收尾。

条件写成**函数调用**，可用 `&&` 组合：

```dae
routing {
    domain(suffix: doubleclick.net) -> block
    fallback: direct
}
```

**可用条件：**

| 函数 | 匹配内容 |
| ------ | ---------- |
| `domain(suffix: x)` / `domain(keyword: x)` / `domain(full: x)` / `domain(regex: x)` / `domain(geosite: x)` | 域名 / geosite |
| `dip(cidr, ...)` / `dip(geoip: cn)` | 目的 IP / geoip |
| `sip(cidr, ...)` | 源 IP |
| `dport(80, 443)` / `sport(...)` | 目的 / 源端口 |
| `l4proto(tcp)` / `l4proto(udp)` | 四层协议 |
| `ipversion(4)` / `ipversion(6)` | IP 版本 |
| `pname(dnsmasq)` | 进程名 |
| `mac('aa:bb:...')` | MAC 地址 |
| `dscp(4)` | DSCP |

出站目标：`direct`、`block`，或任意 **组 / 节点** 名称。

**Must 规则**（`-> direct(must)`）：命中不终结，继续匹配并传播 must 语义（兼容 Go dae）。Clash 的 Global/Direct 模式不会覆盖 must/block。

Geo 资源：将 `geoip.dat` / `geosite.dat` 放到运行时可加载的位置（开发时常用仓库根目录副本）。geosite 类目支持 dae 的属性过滤：`domain(geosite: category-games@cn)` 只保留带 `@cn` 属性的条目（属性名大小写不敏感；第一个 `@` 之后整体作为选择器）。展开为零匹配的 code（类目不存在或属性无命中）会告警且永不命中。

### 路由片段

```dae
routing {
    pname(dnsmasq) && l4proto(udp) && dport(53) -> direct(must)
    dip(geoip: private) -> direct(must)
    domain(geosite: geolocation-cn) -> direct
    domain(suffix: google.com) -> proxy
    fallback: direct
}
```

### 节点失效时的行为（fail-closed 语义）

honk 的数据面与 Go dae 一样是 fail-closed：健康检查判定 outbound 死亡后，eBPF 会**直接丢弃**路由到该 outbound 的新流（`TC_ACT_SHOT`)。如果 `fallback` 指向单个节点，节点死亡意味着所有代理流量被丢——这是有意设计（不做静默直连泄漏），不是 bug。53 端口 DNS(TCP 与 UDP）始终豁免，仍会到达控制面，因此配一条直连 DNS 上游可以在节点故障期间保住域名解析。

为保证路由器自身在任何情况下都可达：

- honk 启动和每次 reload 时会自动注入 `dip(<所有 lan/wan 接口地址>) -> direct(must)`，管理后台 / SSH / clash API 不依赖节点健康。
- 建议加 `dip(geoip: private) -> direct(must)` 覆盖 LAN 内其他设备（打印机、NAS、其他路由），与 dae 示例配置一致，零成本。
- 公网韧性：`fallback` 指向 `fallback` 策略组（≥2 个节点自动切换），并至少保留一条直连 DNS 上游（如 `udp://223.5.5.5`)。

## 9. DNS

```dae
dns {
    ipversion_prefer: 4
    optimistic_cache: true        # 缓存开关
    # 正缓存固定 TTL（覆盖应答 min TTL，并改写 wire RR TTL）。0 = 沿用上游应答 TTL。
    optimistic_cache_ttl: 600
    max_cache_size: 10000
    upstream {
        alidns: 'udp://223.5.5.5:53'
        # 经代理：google: 'https://dns.google/dns-query' -> proxy
    }
    routing {
        request {
            # qname / qtype / && / ! — 与流量 routing 同语法
            qname(geosite: category-ads-all) -> reject
            qname(suffix: cn) -> alidns
            qtype(https) -> reject
            qtype(a, aaaa) -> alidns
            fallback: alidns   # 也可 asis | reject | 命名上游
        }
        response {
            # accept | reject | 命名上游（重查，深度 ≤ 3）
            upstream(googledns) -> accept
            ip(geoip: private) && !qname(geosite: cn) -> googledns
            fallback: accept
        }
    }

    fixed_domain_ttl {
        ddns.example.org: 10
        nocache.test: 0        # 0 = 不缓存
    }
}
```

上游 URI 协议前缀：`udp://`、`tcp://`、`tcp+udp://`、`tls://`、`https://`、`h3://`、`quic://`；无前缀按 UDP 处理。

**request 动作：** 命名上游、`reject`（空成功应答）、`asis`（拨向拦截包原始 DNS 目标）。
**response 动作：** `accept`、`reject`、或命名上游重查。

**当前限制：**

- DoT / DoH（HTTP/2）/ DoQ / DoH3 已实现，并做会话复用（TLS 空闲池、H2 多路复用、单 QUIC 连接）。DoQ/DoH3 暂不支持代理隧道。
- **拨号路径（对齐 dae）：**
  - 显式：`name: 'uri' -> <节点|组>` 强制该出站（组走 GroupManager 策略）。
  - 隐式（无 `->`）：解析 DNS 上游 IP/主机名，用流量 `routing { }` 再判一次出站，再经 GroupManager 选 leaf——等同 dae 的 `chooseBestDnsDialer`。
  - H2/TLS 会话按 **leaf 节点** 缓存。旧写法 `outbound: tag` 仍接受。
- 内部 `sub()` / `node()` / `subnode()` 选择器会解析并忽略（仅客户端 DNS）。

**兼容性与生命周期：**

- 未配置 `ipversion_prefer` 时保留实际的 `DnsConfig` 默认值 `both`，符合资格的
  A 与 AAAA 工作并发执行。设置 `4` 或 `6` 选择相应的偏好模式；没有新增配置面。
- 缓存与 singleflight 仅适用于标准单问题 QUERY：answer/authority 计数为零，最多
  一个无 option 的 EDNS-v0 OPT。受支持的 RD/AD/CD 与 DO 状态、精确 question wire、
  UDP size、调用方 profile、策略和逻辑目的地都属于 identity。多问题、异常 flags、
  EDNS option（包括 ECS/COOKIE）和 EDNS-v1 请求仍会转发，但绕过缓存与合并。
- 重载一次发布包含策略、路由、组、transport 与投影的完整 DNS runtime generation。
  已有请求在旧 generation 上持有 lease，新请求使用替换版本。runtime 退役与池化
  transport 关闭都有界且会被等待。
- DNS 可观测性仅供内部使用。相互独立、单调递增的 atomic counter 使请求记录保持
  non-blocking。内部 best-effort scrape 逐项读取，不承诺 counter 之间的一致性。
  失败日志仅使用有界 `error_kind` 分类和 transport label 等有界字段，不记录 query name、
  upstream 地址或自由格式 error payload。没有新增 DNS endpoint、配置项或 API。

## 10. 订阅（subscription）

```dae
subscription {
    my-sub: 'https://example.com/sub'
}
```

dae 语法仅支持 `tag: 'url'` 形式；`sub_type`（simple | clash | sip008 | custom）、`update_interval`（秒，默认 86400，0 = 仅手动）、`enabled` 等字段使用默认值，在 dae 语法中不可设置。

- 启动拉取有短截止时间；迟到结果经控制面通道合并。
- 订阅节点**只在内存中**（不会回写配置文件）。
- 正文中的分享链接由 `Node::from_share_link` 解析。

## 11. Experimental

### Clash API

```dae
experimental {
    clash_api {
        external_controller: '127.0.0.1:9090'  # 空 = 关闭
        external_ui: 'yacd'
        secret: 'change-me'
        default_mode: 'Rule'                   # Rule | Global | Direct
    }
}
```

常用接口：`/proxies`、`/proxies/{name}`（PUT 切换 Selector）、delay、`/connections`、`/traffic`、`/logs`、`/dns/query`、`/stats`。

环境变量：`HONK_UI_DOWNLOAD_URL` 可覆盖默认 zashboard zip（当 `external_ui` 目录为空/不存在时后台下载）。下载走与用户流量相同的路由判定（Router + 组选择）：`direct` 直连下载，`block` 放弃下载，其余 outbound 经所选节点隧道下载。

### 缓存文件

```dae
experimental {
    cache_file {
        enabled: true
        path: 'cache.db'
        cache_id: ''
        store_fakeip: false   # 仅有前缀/API；完整 FakeIP 引擎未完成
        store_dns: true       # 跨重启持久化 DNS 应答
    }
}
```

持久化 Selector 选择与 Clash 模式。DNS 应答使用 `dns:v2:` key 命名空间下的版本化
`HDNS` 记录。升级时此命名空间冷启动：旧 DNS 行既不导入也不删除。恢复仅接受未过期、
结构正确且 wire identity 与策略相符的行。回滚到 v2 之前的版本时会忽略 v2 行，因此
这些行可以安全留在 `cache.db` 中。

## 12. 使用配置运行

```bash
# 真实 eBPF（需 root）
sudo ./target/release/honk-core --config /etc/honk/config.dae

# 外部 BPF 目标文件
sudo ./target/release/honk-core \
  --config /etc/honk/config.dae \
  --bpf-object /etc/honk/honk-ebpf.o

# 开发：无内核 eBPF
cargo run --release -p honk-core -- \
  --config config.min.dae --mock-ebpf --debug
```

CLI 参数：`--config` / `-c`、`--bpf-object` / `-b`、`--bpf-pin-root`、`--debug` / `-d`、`--mock-ebpf`。

子命令：`mode`、`proxy`、`delay`（详见 [components.zh.md](./components.zh.md)）。

## 13. 校验建议

1. 以仓库根目录的 `config.dae`（完整）或 `config.min.dae`（最小）为起点。
2. 确保 routing / dns / 组的 `final` 中的名称指向真实组、节点、`direct` 或 `block`。
3. 首连域名规则：使用 `dial_mode: domain` / `domain++`，或让 DNS 走 honk 以填充域名位图。
4. 修改组/策略后，SIGHUP 重载会重建 `GroupManager`；仍有效的 Selector 选择会迁移。
5. 若增加示例夹具，可跑 `cargo test -p honk-config` 确认仍能解析。

## 14. 相关文档

- [设计文档](./design.zh.md)
- [组件详细配置](./components.zh.md)
- [DNS 灰度与回滚操作手册](./dns-rollout.zh.md)
- 仓库示例：`config.dae`、`config.min.dae`
