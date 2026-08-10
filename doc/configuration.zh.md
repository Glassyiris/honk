# honk 配置说明

本文说明如何配置 **honk**：配置格式、顶层分段与常用示例。

逐字段的组件级说明（节点/组/DNS/CLI 全表）见 [components.zh.md](./components.zh.md)。

## 1. 配置格式

honk 使用原始的 **dae 配置语法**（`{ section { ... } }`）作为配置格式，配置文件通常以 `.dae` 结尾。语法要点：

- 顶层由若干 `section { ... }` 组成（包括 `include { ... }`）；`#` 为行注释。
- 除 `include` 外，键值对写作 `key: value`；含特殊字符的值用引号包裹（单双引号均可，如 `tcp_check_url: 'https://www.gstatic.com/generate_204'`）。
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

### 运行时数据目录

`global.data_dir` 用于指定不依赖进程 `WorkingDirectory` 的运行时状态根目录。
该值必须是非空绝对路径，默认 `/var/share/honk`；修改后需重启进程。新的相对
`experimental.cache_file.path` 和 `experimental.clash_api.external_ui` 会指向该目录；
订阅持久化也使用其下的 `.sub`。需要时会自动创建父目录；子项的绝对路径保持原样。
为兼容升级，若原配置目录下已有相对缓存、已有 `./.sub`，或工作目录下已有相对 UI
目录，则继续使用它，直至手动移到配置的数据目录。

应将运行期提供的 `geoip.dat`、`geosite.dat` 和相对 `ech_config_path` 放到
`global.data_dir` 下，使 systemd 和手工启动完全一致。显式 `$DAE_LOCATION_ASSET`
的 Geo 目录优先；否则 Geo 文件回退到工作目录和 dae 标准资源目录。为兼容旧部署，
当数据目录中不存在同名文件时，相对 `ech_config_path` 会回退到旧的工作目录相对位置。

## 2. 顶层结构

```text
include { ... }      # 合并其他 .dae 配置文件
global         # 透明代理、健康检查、拨号模式
node           # 代理节点（分享链接）
group          # 节点/嵌套组的选择策略
routing        # 有序流量规则 + fallback
dns            # 上游、DNS 路由、缓存
subscription   # 远程节点列表
experimental   # clash_api、cache_file、udp_nfqueue
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
    tcp_check_url: 'https://www.gstatic.com/generate_204'
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
    tcp_check_url: 'https://www.gstatic.com/generate_204'
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
    udp_nfqueue {
        enabled: false
    }
}
```

## 5. Global 要点

| 主题 | 关键字段 | 建议 |
| ------ | ---------- | ------ |
| 拦截网卡 | `lan_interface`、`wan_interface` | 省略 LAN 时不安装任何 LAN hook；已配置的 WAN hook 仍代理本机发起的 TCP/UDP。`auto` 跟随 IPv4 默认路由；没有默认路由时保持待定，并在网卡、地址或路由变化后自动挂载，无需重启；网关本机地址的 `direct(must)` 规则会同时重新发布，受健康状态控制的出站也会立即复测。 |
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

honk 有三套互相独立的预热机制。其上限由已配置的组或显式预算决定，
不会按订阅原始节点数无限膨胀：

| 机制 | 配置项 | 默认 | 说明 |
| ------ | -------- | ------ | ------ |
| 启动裸 TCP 预连接 | `preconnect_node_count` | `'auto'` | 只在启动时执行一轮。`'auto'` 最多尝试 8 个节点（各组当前选中优先，其次配置顺序）；`0` 关闭；显式 `N` 可覆盖全部合格节点，但最多 8 个并发尝试。仅可裸 TCP 池化的协议参与——AnyTLS/QUIC 与内置 `direct`/`block` 一律跳过。 |
| Selector 常驻 | — | 始终启用 | 每个 `selector` 组按配置选中的叶节点都会保持热态；即使显式选中的节点暂时不健康，也不会改暖其他节点。AnyTLS 与 QUIC 协议保留可复用 session/client，其他代理协议保留一条到服务端的裸 TCP。Clash API 切换选择会立即唤醒协调器：不打断活动流，释放旧节点的 warm 所有权并预热新节点。reload 时未变的已选节点延续原资源。 |
| UDP 预热集合 | `udp_warm_node_count` | `0` | 每组每 IP 族取 top `min(N,3)` 个 UDP 叶子，最多并发 4 个尝试，进程级驻留总量封顶为 `4×N`。UDP 与 Selector 是独立所有者；只有两种原因都消失时才释放共享资源。 |
| 并发拨号上限 | `max_concurrent_dials` | `64` | 按 generation 限制物理代理连接和协议握手；Ready 池命中、已热 AnyTLS/QUIC transport 的逻辑流及内置 `direct`/`block` 均不占额度。reload 会更新 replacement 的局部上限，但新旧 generation 始终共享启动时确定的同一个描述符 gate。 |

健康探测不会把冷节点变热，因此 400 节点订阅不会因 `check_interval`
常驻 400 条隧道。Selector 常驻另以 10 秒周期作丢失资源的兜底修复。
`/stats` 的 `warm` 字段可观测当前预热清单（来源 × 热节点数、每协议驻留会话数）。

## 6. 节点与分享链接

节点在 `node { }` 中以**分享链接**声明，格式为 `tag: 'scheme://...'`（tag 即节点名），也接受不带 tag 的裸链接。单引号、双引号均可；解析失败的条目会在 stderr 打警告并跳过。

解析支持的 scheme：`ss://`、`socks5://`、`trojan://`、`vmess://`、`vless://`、`hysteria2://`、`tuic://`、`juicity://`、`anytls://`。

分享链接中的参数会映射到 `Node` 字段：`name`、`protocol`、`address`/`host`、`port`、`password`/`username`、`encryption`、`tls`、`sni`、`transport`、`ws_path`、`ws_host`、`grpc_service`，以及 Hy2/TUIC/Juicity/AnyTLS 专用字段。

完整字段表与协议注意点（含 UDP 支持矩阵）见 [components.zh.md](./components.zh.md)。

## 7. 组（group）

```dae
group {
    proxy {
        filter: subtag('my-sub') && !name(keyword: 'ExpireAt-')
        filter: name('us1')              # 另一条 filter 与本行是 OR
        filter: group('hk', 'jp')        # 嵌套子组（可选）
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
| `name(regex: '^HK-')` | 正则匹配 |
| `subtag('my-sub')` | 只选择 `subscription { ... }` 中该精确 tag 产生的节点 |
| `subtag(regex: '^paid-', free)` | 订阅 tag 的正则或精确候选 |
| `subtag('my-sub') && !name(keyword: 'ExpireAt-')` | 同一行内 AND；`!` 对单个条件取反 |
| `group('hk')` / `group('hk', 'jp')` | 嵌套子组 |

经验规则：

- **无** filters 且 **无**嵌套组 → 包含**全部**节点。
- 仅有嵌套组 → **不会**自动吞入全部节点。
- 每条 `filter:` 行之间是 OR；同一行以 `&&` 连接的条件是 AND，条件前加 `!` 表示取反。
- `name(...)` 与 `subtag(...)` 均区分大小写。`subtag` 使用 `subscription` 中冒号左侧的 tag，静态节点不会匹配。

**策略：**

| 策略 | dae 写法 | 行为 |
| ------ | ---------- | ------ |
| `selector` | `fixed(0)`、`select` | 手动固定 |
| `urltest` | `min_moving_avg`、`min_avg10`、`min_last_delay` | 最低延迟 + tolerance；TCP/UDP 分离 |
| `loadbalance` | `roundrobin`、`round_robin`、`balance` | 存活成员轮询 |
| `fallback` | `fallback` | 声明顺序第一个存活；粘性 |

## 8. 路由（routing）

规则有序，按源码书写顺序匹配（靠前优先），以 `fallback:` 收尾。matcher 的括号参数列表可以跨物理行书写，直到 `-> 出站` 仍算同一条规则。

条件写成**函数调用**，可用 `&&` 组合：

```dae
routing {
    domain(suffix: doubleclick.net) -> block
    sip(10.10.10.24/32,
        10.10.10.25/32
    ) -> direct
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

Geo 资源：将 `geoip.dat` / `geosite.dat` 放到 `global.data_dir` 下，即可避免受
服务工作目录影响。显式 `$DAE_LOCATION_ASSET` 目录优先；否则加载器回退到工作目录
和 dae 标准资源目录。geosite 类目支持 dae 的属性过滤：
`domain(geosite: category-games@cn)` 只保留带 `@cn` 属性的条目（属性名大小写
不敏感；第一个 `@` 之后整体作为选择器）。展开为零匹配的 code（类目不存在或
属性无命中）会告警且永不命中。

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
    # 未设置 bind 时不启动独立监听。
    # bind: 'tcp+udp://:1053'
    ipversion_prefer: 4
    use_host: true
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

`use_host` 默认为 `false`。启用后，honk 会在构建每个 DNS runtime generation 时
加载 `/etc/hosts`。IN class 的 A/AAAA 查询命中后，会先于 request routing、缓存查询
和上游交换直接应答；名称存在但缺少所请求的地址族时返回 NOERROR/NODATA，其他查询
类型继续走原有管线。查询热路径只读不可变快照，SIGHUP 会重新加载；文件不可读会令
启动失败，或令新的 reload generation 构建失败并保留旧 generation。合成记录的 TTL
为 60 秒，且不写入 honk DNS 缓存。

上游 URI 协议前缀：`udp://`、`tcp://`、`tcp+udp://`、`tls://`、`https://`、`h3://`、`quic://`；无前缀按 UDP 处理。

### 独立监听（`dns.bind`）

`bind` 可省略；省略或设为空只会关闭独立监听，透明 TCP/UDP 53 端口拦截仍照常
工作。只接受当前 dae 的下列形式：

```dae
dns {
    bind: '127.0.0.1:1053'          # 裸数字 IP:port：仅 UDP
    # bind: 'udp://localhost:1053'   # 主机名必须带 scheme
    # bind: 'tcp://[::1]:1053'       # IPv6 字面量必须加方括号
    # bind: 'tcp+udp://:1053'        # 空 host：通配地址，TCP+UDP
}
```

每种形式都必须显式写端口；端口 `0` 表示让内核分配临时端口，最终地址会写入启动
日志。裸主机名 `localhost:1053` 无效，userinfo、path、query 与 fragment 也不接受。
主机名按系统解析顺序尝试，选择第一个能让全部请求 transport 成功 bind 的地址。
目前不支持 IPv6 zone identifier；请改用带方括号的 global、ULA 或 loopback 字面量。

监听器在 host netns 中使用普通、未打 mark 的 socket。LAN 侧已有的本地 TCP 或 UDP
`:53` 监听对相应 transport 优先；通配 socket 只有在目的地址属于本机时才优先，因此
发往远端 resolver 的查询仍走透明路径。通配或 LAN bind 会暴露一个没有应用层认证的
递归 resolver；必须用主机防火墙限制来源，不能发布到不可信网络。

独立请求与透明请求共享同一套 generation-pinned request/response routing、缓存、
singleflight、上游连接池与路由投影。只接受完整的单问题 DNS 请求：多问题 UDP 请求
返回 FORMERR，多问题 TCP stream 在转发前关闭。UDP 应答将客户端 EDNS size 钳制到
`512..=1232` 字节；通配监听会保留查询命中的本地目的地址作为应答源地址。透明与
独立 TCP 都支持 RFC 7766 双字节 framing 与持久连接，并将每次长度/正文读取及应答
写入限制在 30 秒内；独立监听另受不超过全局连接预算四分之一的容量限制。

启动采用 all-or-nothing：所有选中的 socket 都成功 bind 后才算启动成功；任一
bind 失败会关闭其他已选 socket 并令进程启动失败。监听器归进程所有。SIGHUP
可以重载共享 DNS runtime，但 `bind` 的语义变化（host、port 或 transport 集合）
会被拒绝并提示必须重启。

**request 动作：** 命名上游、`reject`（空成功应答）或 `asis`。透明查询的 `asis` 会使用客户端原 transport 拨向拦截包的原始 DNS 目标；UDP 应答带 TC 时会改用 TCP 重试。拨号/connect timeout 单独计时；连接/会话取得后，每次尝试只使用一个覆盖完整请求写入与应答读取的绝对 DNS query deadline。transport 最多重试一次，因此总时长受两次 query deadline 加有界 reset/setup 约束。独立查询没有原始目的地址，因此 `asis` 返回 DNS 失败，而不会递归拨回监听器。
**response 动作：** `accept`、`reject`、或命名上游重查。所有生产 service 路径都会先校验精确 question 与完整 response wire，再发布到缓存。

**当前限制：**

- DoT / DoH（HTTP/2）/ DoQ / DoH3 已实现，并做会话复用（TLS 空闲池、H2 多路复用、单 QUIC 连接）。DoQ/DoH3 暂不支持代理隧道。
- **拨号路径（对齐 dae）：**
  - 显式：`name: 'uri' -> <节点|组>` 强制该出站（组走 GroupManager 策略）。
  - 隐式（无 `->`）：解析 DNS 上游 IP/主机名，用流量 `routing { }` 再判一次出站，再经 GroupManager 选 leaf——等同 dae 的 `chooseBestDnsDialer`。
  - H2/TLS 会话按 **leaf 节点** 缓存。旧写法 `outbound: tag` 仍接受。
- 内部 `sub()` / `node()` / `subnode()` 选择器会解析并忽略（仅客户端 DNS）。

**兼容性与生命周期：**

- 未配置 `ipversion_prefer` 时保留实际的 `DnsConfig` 默认值 `both`，符合资格的
  A 与 AAAA 工作并发执行。设置 `4` 或 `6` 选择相应偏好模式；其 sibling 查询会
  保留调用方的完整 wire profile，只修改 QTYPE。
- 缓存与 singleflight 仅适用于标准单问题 QUERY：answer/authority 计数为零，最多
  一个无 option 的 EDNS-v0 OPT。受支持的 RD/AD/CD 与 DO 状态、精确 question wire、
  UDP size、调用方 profile、策略和逻辑目的地都属于 identity。多问题请求会在策略
  规划前被拒绝；异常 flags、EDNS option（包括 ECS/COOKIE）和 EDNS-v1 请求仍会转发，
  但绕过缓存与合并。
- 重载一次发布包含策略、路由、组、transport 与投影的完整 DNS runtime generation。
  已有请求在旧 generation 上持有 lease，新请求使用替换版本。runtime 退役与池化
  transport 关闭都有界且会被等待。
- DNS 可观测性仅供内部使用。相互独立、单调递增的 atomic counter 使请求记录保持
  non-blocking。内部 best-effort scrape 逐项读取，不承诺 counter 之间的一致性。
  失败日志只使用有界 `error_kind` 分类和 transport label 等有界字段，不记录 query name、
  upstream 地址或自由格式 error payload。这些内部遥测不会新增公开 DNS metric 或 API。

## 10. 订阅（subscription）

```dae
subscription {
    my-sub: 'https://example.com/sub'
}
```

dae 语法仅支持 `tag: 'url'` 形式；`sub_type`（simple | clash | sip008 | custom）、`update_interval`（秒，默认 86400，0 = 仅手动）、`enabled` 等字段使用默认值，在 dae 语法中不可设置。

- `global { store_subscribe: true }` 默认开启。成功获取且解析通过的原始正文会原子保存到 `global.data_dir` 下的 `.sub`，目录权限 `0700`、文件权限 `0600`；已有旧 `./.sub` 会继续使用，直至手动迁移。缓存正文不会写回配置文件，请求身份只以散列文件名出现。
- 启动时先恢复有效缓存。已有缓存的订阅可立即启动，同时继续后台联网刷新；无缓存的订阅仍保留 5 秒首次拉取等待时间。
- SIGHUP 重载先沿用当前订阅节点；已启用但没有可沿用节点的订阅会从缓存恢复。拉取、解析或写入失败不会清空当前节点或上一次有效缓存；损坏缓存会被忽略，直到一次有效刷新替换它。
- 订阅节点仍只存在于运行时，不会回写配置文件。修改 `store_subscribe` 后需重启进程。
- 正文中的分享链接由 `Node::from_share_link` 解析。

Clash YAML 的 VLESS 条目会在派生节点 ID 前映射 `uuid`（兼容旧
`password`）、`servername`（回退到 `sni`）、`flow` 与 `network`。嵌套
`reality-opts` 映射 `public-key`、`short-id`、`spider-x`（缺省 `/`）并启用
REALITY TLS 承载；嵌套 `ws-opts` 映射 `path` 及大小写不敏感的
`headers.Host`，`grpc-opts` 映射 `grpc-service-name`。原有扁平 WS/gRPC
别名继续可用。若 VLESS 条目含 `reality-opts` 却没有非空 `public-key`，
该条目会被跳过，不会静默降级成普通 TLS。Clash `client-fingerprint`
不映射，因为 honk 的指纹选择是进程级而非节点级。

VLESS 支持 plain/TLS/REALITY 承载上的 TCP、WS、gRPC；其中
`xtls-rprx-vision` 必须使用 TLS 或 REALITY，且仅支持 TCP。其他 transport
与 flow 只保留用于可见性，`honk-tool sub` 不会拨号；VLESS 没有 UDP
packet handler。

## 11. Experimental

### 首包保留 UDP NFQUEUE

```dae
experimental {
    udp_nfqueue {
        enabled: true
    }
}
```

`enabled` 是唯一设置，默认 `false`。修改
`experimental.udp_nfqueue.enabled` 后必须重启；SIGHUP 重载会拒绝该变化。
启用时必须使用带 `ebpf` feature 的构建和真实 eBPF 后端。不带 `ebpf` 的构建或
使用 `--mock-ebpf` 的运行会在启动时被拒绝，不会静默回退。

该路径**仅覆盖 LAN 转发 UDP**：主机的 `inet prerouting` 位于 LAN TC 暂存点之后；
本机发起的 WAN 出口流量仍走规范 TPROXY 路径。53 端口、内部/特殊流量、`must`、
`block`、反向流量以及已经可以安全地在路由时直连的决策均被排除。只有在用户态路由或
域名/QUIC 检查后仍可能改判的歧义决策才会暂存。

honk 通过 raw netlink 绑定唯一且固定的 NFQUEUE `320`，不启用 bypass、fanout 或
fail-open。它拥有名称精确为 `inet honk_nfqueue` / `udp_decision` 的 nftables 表与链。
honk 运行期间，同一网络命名空间中的防火墙管理器不得 flush、替换或修改任一对象。
eBPF `UDP_DECISION_SEQUENCE` pin 会跨普通重启和清理保留。token 由两位 generation 与
28 位 sequence 组成。pin 保留旧版本的 12 字节布局，并在 `next` 中保存完整 raw token；
启动只校验、不改写，因此回滚到上一 binary 时会从同一边界继续分配而不复用 token。
正常升级/降级必须保留该 pin。只有启动明确拒绝损坏或不兼容的 pin 时，才应保持
NFQUEUE fenced，停止所有 honk 进程，确认队列和 token 绑定 map 已消失，再删除一次 pin
并重启；仍有队列或 token 绑定 map 存活时删除会复用活动 token。耗尽时先 fence 并
排空暂存；只有候选 generation 及其到 generation 3 的所有更高 generation 都未出现在
任何存活 token 绑定 map 中，才能切换。旧 allocator 只会沿该区间单调递增，因此回滚
后不会复用 token。若没有满足条件的候选，则按 1、2、5、30 秒退避重试：无需暂存的
UDP 继续工作，新的歧义流 fail closed；正常运行无需重启系统或手工重置 allocator。

原始 skb 在 conntrack/NAT 之前被保留。Direct 执行 token 校验的
Arm → 按 FIFO 以最终 mark `NF_ACCEPT` → Activate，不创建用户态直连 socket、
payload 副本、endpoint、connection 条目，也不故意触发重传。Proxy 提交 token 绑定
状态，把唯一的保留 payload 副本转交给现有 UDP 初始化器，丢弃原始 skb，并且只
拨号/发送一次。Block 和取消会丢弃原始 skb。重载与关闭先清除 readiness，静默并取消
待定所有权，再拆除队列及自有表。队列、listener 和 verdict 错误仍为致命错误，不会
fail-open；分配器耗尽使用带 fence 的 generation 轮换恢复。

ingest actor 最多接纳 256 个报文和 8 MiB 保留 payload。典型 1,200 字节负载先达到
项数上限；65,507 字节的最大 UDP payload 在 128 个排队报文时达到字节上限。
correlator 另将存活 flow cell 限制为 4,096 个，并将每条流的保留 verdict 限制为 64 个。
slow-path permit 在 actor 出队时获取，而不是在请求等待队列时预占。绝对保留期限从
listener 收包起固定为三秒，既包含 Arm 前的 backend 锁获取，也包含 Arm 后 Activate
的锁获取。队列满或超期时直接丢弃，既不让内存继续增长，也不绕过策略。

启用 Clash API 后，`GET /stats` 暴露固定对象 `/stats.udp.nfqueue`（点路径，不是
独立路由）：`received`、`activeFlows`、`kernelQueueDepth`、
`kernelStatsAvailable`、`kernelStatsReadErrors`、`kernelDropped`、
`kernelUserDropped`、`heldPackets`、`heldPeak`、`socketReceiveBufferBytes`、
`actorQueueFull`、`correlatorFull`、`actorQueueDepth`、`actorQueuedBytes`、
`actorOldestAgeNanos`、`directAccepted`、`proxyCopied`、`proxyDropped`、`block`、
`cancel`、`drop`、`tokenMismatch`、`tokenExhaustion`、`tokenRollovers`、
`verdictErrors` 和 `receiptToVerdict`。字段含义见组件参考。

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

环境变量：`HONK_UI_DOWNLOAD_URL` 可覆盖默认 zashboard zip（当 `external_ui` 目录为空/不存在时后台下载）。相对 `external_ui` 优先使用 `global.data_dir` 下的已有目录，再使用已有工作目录相对目录；目录均不存在时在 `global.data_dir` 下创建。绝对路径保持原样。下载走与用户流量相同的路由判定（Router + 组选择）：`direct` 直连下载，`block` 放弃下载，其余 outbound 经所选节点隧道下载。

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

新的相对 `path` 解析到 `global.data_dir`；需要将数据库置于其他位置时请使用绝对路径。若 `<global.data_dir>/<path>` 不存在，则保留原配置目录下已有的相对路径，直至手动迁移。

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
5. 修改 `experimental.udp_nfqueue.enabled` 后必须重启进程；启用时应确认使用真实 eBPF 后端，且防火墙管理器不会修改 `inet honk_nfqueue` / `udp_decision`。
6. 若增加示例夹具，可跑 `cargo test -p honk-config` 确认仍能解析。

## 14. 相关文档

- [设计文档](./design.zh.md)
- [组件详细配置](./components.zh.md)
- [DNS 灰度与回滚操作手册](./dns-rollout.zh.md)
- 仓库示例：`config.dae`、`config.min.dae`
