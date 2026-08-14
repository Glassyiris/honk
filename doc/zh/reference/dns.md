# DNS 配置参考

本文定义当前 dae 语法的 `dns { ... }` 段及其运行时语义。

## 顶层键

| 键 | 默认值 | 含义 |
| --- | --- | --- |
| `bind` | 省略 / `""` | 可选的独立 DNS 监听器；空值只关闭此监听器。 |
| `use_host` | `false` | 使用每个 DNS runtime generation 对应的一份 `/etc/hosts` 快照应答匹配的 IN class A/AAAA 查询。 |
| `upstream { ... }` | `default: 'udp://223.5.5.5:53'` | 命名上游服务器。第一个显式 `upstream` 块会替换内置条目。 |
| `routing { ... }` | 无规则；request fallback 为 `default`；response fallback 为 `accept` | 有序的 request 与 response 路由。 |
| `ipversion_prefer` | 省略：`both` | `4` 选择 `preferipv4`；`6` 选择 `preferipv6`。 |
| `optimistic_cache` | `true` | 启用正、负缓存的读取与写入。 |
| `optimistic_cache_ttl` | `600` 秒 | 固定的正应答缓存和 wire TTL；`0` 保留应答 TTL。 |
| `max_cache_size` | `10000` | 缓存最大条目数，也是保留 wire 字节预算的输入。 |
| `fixed_domain_ttl { ... }` | 空 | 按域名覆盖正应答 TTL；`0` 表示该域名永不缓存。 |

## 独立监听器（`bind`）

独立监听器使用 host 网络命名空间中的普通、未打 mark 的 socket。关闭独立监听器时，透明 TCP/UDP 53 端口拦截仍然生效。

| 值 | 结果 |
| --- | --- |
| 省略或 `""` | 不创建独立监听器。 |
| 数字 `IP:port`，如 `127.0.0.1:1053` 或 `[::1]:1053` | UDP 监听器。 |
| `udp://host:port` | UDP 监听器。 |
| `tcp://host:port` | TCP 监听器。 |
| `tcp+udp://host:port` | 在同一地址和端口创建 TCP 与 UDP 监听器。 |

主机名必须带 scheme，例如 `udp://localhost:1053`。IPv6 字面量必须使用方括号。`tcp+udp://:1053` 这样的空 host 表示通配地址。每种形式都必须显式给出十进制 `u16` 端口。端口 `0` 表示申请临时端口；honk 会记录最终选择的地址。

裸主机名无效。解析器也会拒绝 userinfo、path、query、fragment、反斜杠、IPv6 zone identifier、错误的方括号、不支持的 scheme 和超出范围的端口。使用主机名时，honk 按系统解析顺序尝试地址，并使用第一个能让全部请求 transport 成功 bind 的地址。bind 同步且 all-or-nothing：任一失败都会关闭其他已选 socket 并令启动失败。

监听器归进程所有。SIGHUP 重载接受语义等价的不同写法，但 host、port 或 transport 集合的任何变化都会作为 restart-required 被拒绝。通配或 LAN 侧 bind 会暴露一个无认证的递归 resolver；必须用主机防火墙限制来源，绝不能发布到不可信网络。

## Hosts 快照（`use_host`）

`use_host: true` 时，honk 会在构建每个 DNS runtime generation 时读取 `/etc/hosts`。查询路径只使用该不可变快照，不执行文件 I/O。有效地址行中的规范名和别名按精确、ASCII 大小写不敏感的名称建立索引；末尾点会被归一化，重复地址会被去重。

在 `ipv4only`/`ipv6only` 的硬地址族过滤之后，已知名称的 IN class A 或 AAAA 查询优先于 request 规则（包括 `reject`）、缓存查询和上游交换。名称存在但没有所请求地址族时，honk 返回 NOERROR/NODATA，且不查询上游。其他 class 和 qtype 继续走正常管线。Hosts 应答使用 60 秒 TTL，并绕过 honk 的 DNS 缓存。

SIGHUP 会构建新快照。若 `/etc/hosts` 不可读，启动失败；重载时，替换 generation 会在发布前失败，当前 generation 继续使用。

## 上游

每行使用 `name: 'uri'`，后面可选 `-> node-or-group`：

```dae
upstream {
    default: 'udp://223.5.5.5:53'
    google_doh: 'https://dns.google/dns-query' -> proxy
}
```

### URI scheme 与默认值

| URI 形式 | 运行时协议 | 默认端口 / path |
| --- | --- | --- |
| `host[:port]` 或 `udp://host[:port]` | UDP；应答带 `TC` 时改用 TCP 重试 | `53` |
| `tcp://host[:port]` | TCP DNS | `53` |
| `tcp+udp://host[:port]` | 当前解析器将其归一化为上面的 UDP 行为 | `53` |
| `tls://host[:port]` | DNS over TLS（DoT） | `853` |
| `https://host[:port][/path]` | DNS over HTTPS（DoH，HTTP/2） | `443`，path 为 `/dns-query` |
| `h3://host[:port][/path]` 或 `http3://host[:port][/path]` | DNS over HTTP/3（DoH3） | `443`，path 为 `/dns-query` |
| `quic://host[:port]` | DNS over QUIC（DoQ） | `853` |

对于基于 TLS 的协议，解析器会从主机名派生 `tls_server_name`。当证书校验要求 DNS 名称时，IP 字面量 endpoint 需要显式 query 参数：

```dae
cloudflare_dot: 'tls://1.1.1.1:853?tls_server_name=cloudflare-dns.com'
```

该参数会从拨号地址中移除，并覆盖从主机名派生的值。

### 出站选择

末尾的 `-> tag` 强制该上游经过指定节点或组。省略时，honk 会解析上游目的地址并应用普通流量的 `routing { ... }` 规则；该路由仍可选择代理 leaf。旧版同一行写法 `name: 'uri' outbound: tag` 仍然接受。

| 协议 | 经过选定节点/组 |
| --- | --- |
| UDP（`udp`、裸地址、`tcp+udp`） | 通过该出站承载为 TCP-DNS。 |
| TCP | 支持通过出站 TCP stream。 |
| DoT | 支持；TLS 在出站 TCP stream 上运行。 |
| DoH | 支持；TLS 与 HTTP/2 在出站 TCP stream 上运行。 |
| DoQ | 不支持；只能直连。 |
| DoH3 | 不支持；只能直连。 |

## DNS 路由

`routing` 包含有序的 `request` 和 `response` 规则，首条匹配规则生效。同一个条件内的参数按 OR 组合；用 `&&` 连接的条件按 AND 组合。在条件前加 `!` 可将其取反。

### 条件

| 语法 | 范围 | 含义 |
| --- | --- | --- |
| `qname(suffix: example.com)` | Request 与 response | 点边界后缀；裸参数也表示后缀。 |
| `qname(keyword: ads)` | Request 与 response | 子串匹配。 |
| `qname(full: api.example.com)` | Request 与 response | 精确域名匹配。 |
| `qname(regex: ...)` | Request 与 response | Rust 正则表达式匹配。 |
| `qname(geosite: cn)` | Request 与 response | 匹配由指定 geosite 代码展开的域名。 |
| `qtype(a, aaaa, ...)` | Request 与 response | 匹配 QTYPE 名称或数字 `u16`。可识别名称为 `A`、`AAAA`、`CNAME`、`MX`、`TXT`、`NS`、`PTR`、`SOA`、`SRV`、`HTTPS`、`SVCB`、`ANY` 和 `*`。 |
| `upstream(name, ...)` | 仅 response | 匹配生成当前应答的上游。 |
| `ip(192.0.2.0/24, geoip: private, ...)` | 仅 response | 任一应答 IP 属于所列 CIDR 或 GeoIP 集时匹配。 |

### Request 动作

| 动作 | 结果 |
| --- | --- |
| `reject` | 返回空的成功应答。 |
| `asis` | 拨向拦截所得的原始 DNS 目的地址。透明查询保留入口 transport；UDP 应答带 `TC` 时，对同一目的地址改用 TCP 重试。独立查询没有原始目的地址，会失败而不会递归拨回监听器。 |
| 上游名 | 查询该命名上游。 |
| `fallback: reject\|asis\|<upstream>` | 无 request 规则匹配时使用的动作；默认使用上游 `default`。 |

### Response 动作

| 动作 | 结果 |
| --- | --- |
| `accept` | 返回当前应答。 |
| `reject` | 返回空的成功应答。 |
| 上游名 | 通过该命名上游重新查询，然后再次执行 response 路由。 |
| `fallback: accept\|reject` | 无 response 规则匹配时使用的判定；默认为 `accept`。 |

一次 response 遍历的最大重新查询深度为三个上游，其中包括初始上游；第四次交换会被拒绝。重新查询形成环路时也会被拒绝。

### 旧版转换

兼容性 schema 保留扁平的 `routing.rules` 条目，其中包含 `domain` 和 `upstream`，以及一个命名 `fallback`。不存在新式 request 规则时，honk 会在加载时将其转换成 request 规则。`suffix:`、`keyword:`、`full:` 和 `regex:` 前缀选择 matcher；不带前缀的旧版域名是精确 `full` 匹配。旧版 fallback 会成为 request fallback。这些是结构化兼容字段，不是额外的当前 dae statement。

## 地址族策略

| dae 设置 | 内部策略 | 行为 |
| --- | --- | --- |
| 省略 | `both` | 并发执行符合资格的 A 与 AAAA 工作；不压制任何地址族。 |
| `ipversion_prefer: 4` | `preferipv4` | 偏好 IPv4，同时保留 IPv6 回退。 |
| `ipversion_prefer: 6` | `preferipv6` | 偏好 IPv6，同时保留 IPv4 回退。 |

偏好模式下，两个地址族仍可查询。对于非偏好族的 A/AAAA 请求，honk 会让偏好族 sibling query 经过同一管线，并保留调用方除 QTYPE 外的 wire profile。偏好族有地址时，非偏好族应答会被压制为 NODATA；偏好族没有地址或 sibling query 失败时，则返回非偏好族应答。相关缓存未命中时，这会增加一次上游查询。

同一策略也决定上游主机名经 bootstrap 解析后的地址拨号顺序。`both` 与 `preferipv4` 先拨 IPv4；`preferipv6` 先拨 IPv6。TCP、DoT、DoH、DoQ、DoH3 以及经代理承载的 DNS 会在拨号失败后继续尝试后续地址。直连 UDP 会把唯一一次重试优先用于另一地址族，再考虑同族的其他地址，并复用成功的 socket。仅兼容格式可用的 `ipv4only` 与 `ipv6only` 会把上游拨号候选限制在对应地址族。

内部 `ipv4only` 和 `ipv6only` 模式无法通过 dae 的 `ipversion_prefer` 语法表达。

## 缓存与固定 TTL

| 键 | 默认值 | 行为 |
| --- | --- | --- |
| `optimistic_cache` | `true` | 启用缓存读取与发布。 |
| `optimistic_cache_ttl` | `600` | 覆盖正应答的最小 TTL，用于缓存生命周期和返回的 wire RR TTL。`0` 保留应答 TTL。 |
| `max_cache_size` | `10000` | 条目上限。它还按每个配置条目 4 KiB 缩放保留 query/response wire 字节预算；每个分片至少 65,535 字节，全局上限 64 MiB。`0` 会告警并钳制为一个条目。 |
| `fixed_domain_ttl { domain: seconds }` | 空 | 先于 `optimistic_cache_ttl` 应用的按域名覆盖；`0` 使该域名不可缓存。 |

例如：

```dae
fixed_domain_ttl {
    ddns.example.org: 10
    nocache.test: 0
}
```

## 示例

```dae
dns {
    # 省略 bind 可保持独立监听器关闭。
    # bind: 'tcp+udp://:1053'
    use_host: true
    ipversion_prefer: 4

    upstream {
        default: 'udp://223.5.5.5:53'
        cloudflare_dot: 'tls://1.1.1.1:853?tls_server_name=cloudflare-dns.com'
        google_doh: 'https://dns.google/dns-query' -> proxy
    }

    routing {
        request {
            qname(geosite: category-ads-all) -> reject
            qname(suffix: cn) -> default
            qtype(https) -> reject
            fallback: default
        }
        response {
            upstream(google_doh) -> accept
            ip(geoip: private) && !qname(geosite: cn) -> google_doh
            fallback: accept
        }
    }

    optimistic_cache: true
    optimistic_cache_ttl: 600
    max_cache_size: 10000
    fixed_domain_ttl {
        ddns.example.org: 10
        nocache.test: 0
    }
}
```

## 相关文档

- [DNS 设计](../design/dns.md)
- [实验性配置参考（`store_dns`）](./experimental.md)
- [全局配置参考](./global.md)
