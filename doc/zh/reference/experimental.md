# Experimental 配置参考

本文档说明 `experimental { ... }` 下当前支持的嵌套 section。

## Section 概览

| 嵌套 section | 用途 |
| --- | --- |
| `clash_api` | Clash 兼容 HTTP API 与外部 dashboard |
| `cache_file` | 用 SQLite 持久化运行时选择、模式、延迟样本和可选 DNS 状态 |
| `native_api` | 独立、显式启用的原生观测/控制、受控 `.dae` 源管理与本地 UI 目录 |

`udp_nfqueue { enabled: ... }` 是已弃用的兼容 section。dae 和结构化配置加载器仍会接受它，打印迁移 warning，并将值复制到 `global.nfqueue_enable`；新配置应直接使用全局字段。

## `native_api`

需要默认编译的 Cargo feature `native-api`，不依赖 `clash-api`，listener 仍默认关闭。未编译该 feature 却启用配置时，启动报错。所有生效字段都要求重启；SIGHUP 拒绝其变更并保留当前 listener 与配置代次。未知字段、标量中的嵌套块、无效布尔值及安全列表空成员均报错。

| 字段 | 默认值 | 含义 |
| --- | --- | --- |
| `enabled` | `false` | 启动独立原生 listener。 |
| `listen` | `"127.0.0.1:9527"` | 数字 IP 与 1–65535 端口，不接受主机名或 `:port` 简写。 |
| `secret` | `""` | 独立于 Clash 的 bearer 凭证。除显式匿名 loopback 外必须配置。API 响应按值遮蔽监听 secret；短于 8 字节的值不遮蔽，启动时会记录提示。 |
| `allow_anonymous_loopback` | `false` | 仅在 secret 为空且实际监听 IP 为 loopback 时允许无凭证请求。配置 secret 后仍必须认证。 |
| `allow_origins` | 空列表 | 额外允许的完整 HTTP(S) Origin；不含路径、凭据、query、fragment、`null` 或通配符。 |
| `allowed_hosts` | 空列表 | 额外允许的 HTTP Host authority；不含 URL scheme、路径、凭据或通配符。省略端口表示 80，不是监听端口。 |
| `ui` | `""` | 空值关闭托管；其他值为含可读 `index.html` 的可信本地目录，或配合默认关闭的 `native-ui` feature 使用 `embedded`。启动不下载、不解压、不构建前端。 |
| `record_flows` | `true` | 允许按 API 客户端连接规则记录有界用户态 flow，或通过显式运行时设置持续记录。`false` 禁止记录，运行时设置不能覆盖；修改配置需重启。 |
| `record_traffic` | `true` | 无客户端也记录流量 history；最多 600 点/600 秒，false 在重启后释放对应缓冲，不关闭即时计数。 |
| `record_memory` | `true` | 无客户端也记录 RSS/cgroup history；最多 600 点/600 秒，false 在重启后释放对应缓冲，不关闭即时内存观测。 |
| `record_logs` | `true` | 允许按 API 客户端连接规则或显式运行时设置捕获结构化日志，最多保留 512 条、60 秒。`false` 禁止捕获；修改配置需重启。控制台和 Clash 日志保持独立。 |
| `record_dns_log` | `true` | 允许按 API 客户端连接规则或显式运行时设置记录客户端 DNS 完成历史，最多保留 512 条、8 MiB。`false` 禁止记录；修改配置需重启。 |
| `probe_allowed_cidrs` | 空列表 | 管理员允许原生 probe 访问的受限 IP CIDR；默认拒绝私网、loopback、link-local 等受限解析目标，包括配置的节点地址。不是任意 URL 许可。 |
| `probe_allowed_ports` | 空列表 | 扩展原生 HTTP/HTTPS 检查的默认 80/443、DNS 检查的默认 53 端口；每项须为 1–65535。Raw TCP-connect 只使用节点实际配置端口，不受此扩展列表限制；受限地址仍需独立 CIDR 许可。 |
| `config_content` | `false` | 为兼容旧配置而接受，不产生作用。认证后的源读取要求非空 `secret`，仅遮蔽监听凭据值。 |
| `config_write` | `false` | 允许已接受主文件及所有已接受 include 的原文替换与 reload，含监听凭据的源除外；要求非空 `secret`。 |
| `writable_includes` | 空列表 | 为兼容旧配置而接受，不产生作用；不授予路径权限，也不限制已接受 include。 |
| `geosite_download_url` | `""` | 更新已加载 geosite 的最终直达 HTTP(S) 来源；要求 `config_write`，已加载该资产而 URL 为空时不能更新。 |
| `geoip_download_url` | `""` | 更新已加载 geoip 的最终直达 HTTP(S) 来源，使用相同授权与限制。 |

```dae
experimental {
    native_api {
        enabled: true
        listen: '127.0.0.1:9527'
        secret: 'operator-supplied-random-token'
        allow_anonymous_loopback: false
        ui: '/usr/share/doona'
    }
}
```

非空原生 secret 必须为不含空白或逗号的可见 ASCII，与 HTTP bearer parser 一致；不支持的字节在共同配置准入处报错，不会启动一个无法认证的 listener。

请替换示例 secret。本地无凭证开发需省略 `secret` 并显式设置 `allow_anonymous_loopback: true`；不能通过反向代理公开该匿名 listener。非 loopback 网络上的明文 HTTP 加 token 不是安全部署，应由可信代理终止 TLS。

默认 Host 只接受具体监听 authority；loopback 另接受同端口的 `localhost`、`127.0.0.1` 与 `[::1]`。通配监听接受同端口的任意 IP 字面量 Host 与 `localhost`，因为这些就是请求到达的那个监听器本身；DNS 名称仍不授权，因为只有名称能被重绑定。只有真实直连对应的明文 HTTP Origin 自动允许。TLS 反代若保留 `Host: panel.example`，需配置 `allowed_hosts: 'panel.example'` 与 `allow_origins: 'https://panel.example'`；若保留 `Host: panel.example:443`，则使用 `allowed_hosts: 'panel.example', 'panel.example:443'`。Forwarded headers 不授予权限。

列表采用逐项引号与逗号分隔，例如 `allow_origins: 'http://localhost:3000', 'https://panel.example'`、`probe_allowed_cidrs: '127.0.0.0/8', '::1/128'`、`probe_allowed_ports: 8080, 8443`。省略表示空列表；不接受 JSON 方括号或整段引号聚合。Probe 会校验并固定解析出的地址，IPv4-mapped IPv6 先规范化为 IPv4；开放端口不自动授权受限 CIDR，也不允许调用方指定任意 URL 或跟随 HTTP 重定向。

相对 UI 路径沿用依赖搜索顺序：`global.data_dir` 下已有路径、`/var/share/honk` 下已有路径、工作目录已有路径；均不存在时定位到 `global.data_dir` 并在启动时报错。目录及其符号链接目标均由可信管理员负责。参见[原生 API 契约](./api.md#原生-api-m1)。

单文件部署可使用 `cargo build -p honk-core --features native-ui` 与 `ui: embedded`；`native-ui` 隐含 `native-api`，不要求 Clash。没有 `native-ui` 时启用内嵌托管会启动失败。访问 `/ui/` 后在真实 doona 登录表单输入 bearer。产物/源码身份、对应源码分发和管理契约见 [API 参考](./api.md#内嵌-doona-来源)。

Geodata 来源由管理员配置、需重启，不能通过源写入修改；拒绝 userinfo、fragment、redirect 与 content encoding。域名来源要求 `global.bootstrap_resolver`，不回退系统 DNS、不选择代理 detour；所有已加载资产都要有配置来源才能更新。[M9 契约](./api.md#主文件条目与-geodata-管理m9)区分网络期限、已验证字节激活及部分耐久替换，不承诺回滚。

### M5：共用采样与可选历史

流量与内存 history 共用既有一秒 sampler，错过 tick 使用 Skip；仅存内存，重启清空，不插值、不补零，缺口与 null 原样保留。读取依据实际 RSS/cgroup v2 文件，不把未知值伪装为零，也不宣称内核内存核算。关闭 history 不关闭即时 runtime、出站或内存读取；所有记录开关仍需重启。已启用的日志/DNS 日志/flow 可通过 `/runtime/settings` 临时调整级别或留存上限，但不能动态开启被配置关闭的 recorder。合并全量校验后原子生效；显式配置激活（含 no-op）恢复配置值，provider/network refresh 保留临时值，见 [API 契约](./api.md#provider日志与临时设置)。

### M6：配置管理的信任边界

配置来源仅在真实 `.dae` 启动加载时捕获；程序内构造的配置或 serde 加载不提供无损源管理。配置读取返回已接受正文，仅遮蔽声明的监听凭据值，包括重复、被覆盖的值及其在其他位置的出现。获准访问的匿名 loopback 请求与 bearer 认证请求读取相同的数据。凭据源仍只读，哈希仍对应原始字节。源 `path` 保持入口目录相对名称，`absolute_path` 提供规范化绝对路径。API 禁止改变或迁移凭据及原生设置；需管理员本地修改并重启。若主文件包含凭据，要先在本地将其移至专用只读 include，再重启，才能通过 API 编辑该主文件。

`config_content` 与 `writable_includes` 仍可配置，但不产生作用。启用 `config_write` 后，所有已接受的非凭据 include 均可写；普通 include 的 glob、排序及无匹配语义不变。全量源/校验预算为 32 个来源、8 MiB，重复依赖实体化也计费；HTTP JSON body 仍最多 64 KiB。源 PUT 使用磁盘字节 SHA-256 强 If-Match，组 PATCH 使用 accepted revision 并独立检查源/依赖。正文披露与写许可独立，遮蔽后的凭据源正文不能回写。Selector、受限组 PATCH 和 M9 主文件创建/删除均复用来源权威；自动策略 override 仍关闭。具体失败恢复见 [API 契约](./api.md#主文件条目与-geodata-管理m9)。


## `clash_api`

| 字段 | 默认值 | 含义 |
| --- | --- | --- |
| `external_controller` | `""` | HTTP 监听地址。空值关闭 API server。 |
| `external_ui` | `""` | 外部 dashboard 目录。空值关闭 dashboard 服务与下载。 |
| `external_ui_download_url` | `""` | HTTP(S) dashboard ZIP URL。空值使用内建 zashboard URL。 |
| `external_ui_download_detour` | `""` | 下载使用的节点或组 tag。空值遵循普通流量路由。 |
| `secret` | `""` | API 鉴权 secret。空值关闭鉴权。短于 8 字节的值在原生 API 响应里不遮蔽。 |
| `default_mode` | `"Rule"` | 启动模式：`Rule`、`Global` 或 `Direct`。有效的缓存模式优先。 |

所有 `clash_api` 字段都由启动阶段持有。通过 SIGHUP 提交的候选配置只要修改其中任一字段就会被拒绝。

### 鉴权与传输

`secret` 非空时，API 请求使用 `Authorization: Bearer <secret>`；WebSocket upgrade 也可以改用 `?token=<secret>`。静态 `/ui` 内容不经过这层鉴权 middleware。内置 listener 只提供明文 HTTP，不提供 TLS。应绑定到 `127.0.0.1` 等 loopback 地址，或在前面部署带鉴权的 TLS reverse proxy；不得直接暴露到不受信任的网络。endpoint 清单见 [Clash API 参考](./api.md)。

显式启用非回环地址监听且 secret 为空时，会在 `experimental.clash_api.external_controller` 产生 `unsafe-api-bind`，结构化输入也不例外。诊断不包含端点或 secret。使用回环地址的示例配置不产生该警告；此警告不会改变监听、鉴权或 CORS 规则。

### 外部 UI

绝对 `external_ui` 路径按原值使用。相对路径首先选择 `global.data_dir` 下的已有目录，其次选择 `/var/share/honk` 下的已有目录，再选择相对当前工作目录的已有目录；都不存在时，honk 在 `global.data_dir` 下创建目标目录。目标缺失或为空时，会在后台下载 dashboard ZIP。非空 `external_ui_download_url` 会替换内建 zashboard URL；`HONK_UI_DOWNLOAD_URL` 的优先级高于两者。

非空 `external_ui_download_detour` 会强制初始请求和每次 redirect 都经过该节点或组。`direct` 直接下载，`block` 中止下载，组则为每次 exchange 解析其权威叶节点。该字段为空时，每个 URL 仍按原有行为遵循普通流量路由。tag 不可用、下载失败或解压失败只写日志，不会停止引擎。

### 启动模式

`default_mode` 接受规范模式 `Rule`、`Global` 和 `Direct`。`cache_file` 已启用且包含有效的 Clash 缓存模式时，改为恢复该值。无效的缓存值或配置值回退到 `Rule`。

## `cache_file`

| 字段 | 默认值 | 含义 |
| --- | --- | --- |
| `enabled` | `false` | 打开 SQLite 缓存并启用运行时状态持久化。 |
| `path` | `"cache.db"` | 数据库路径。对相对路径，依次优先使用 `global.data_dir` 下、`/var/share/honk` 下和相对原配置目录的已有文件；新文件创建在 `global.data_dir` 下。 |
| `cache_id` | `""` | 所有数据库 key 的 namespace。非空值给 key 加上 `<cache_id>:` 前缀。 |
| `store_fakeip` | `false` | 仅表示 FakeIP 持久化意图。已有 `fakeip:` 前缀和 flush API，但引擎尚不写入或恢复映射。 |
| `store_dns` | `false` | 使用 exact-key v2 格式持久化并恢复 DNS 缓存应答。 |

整个 `cache_file` section 都由启动阶段持有。通过 SIGHUP 提交的候选配置只要修改任一字段就会被拒绝。

### 始终持久化的状态

只要 `enabled` 成功打开数据库，honk 就会分别持久化 TCP/UDP Selector 选择和每个节点最后一次真实延迟样本，不受 `store_fakeip` 与 `store_dns` 影响。只有 native 未启用时才恢复/保存 Clash 模式与合成 GLOBAL 选择；native 启用时两种 API 共用临时模式，在启动与成功显式配置激活（含 no-op）时恢复 Rule，provider/network refresh 不重置。延迟样本每分钟生成一次快照；恢复时丢弃格式错误、为零或超过 24 小时的样本。liveness 不会恢复。

### DNS 持久化

`store_dns: true` 时，条目使用 `dns:v2:` key namespace 和 `HDNS` version-2 二进制 payload。v2 namespace 可安全回滚：pre-v2 binary 读取旧 `dns:` namespace 时会排除 `dns:v2:` 行，因此不会改动 v2 数据。

只有未过期，并且 key digest、规范 query wire、response wire identity 与当前 DNS policy 全部匹配的 v2 行才会恢复。exact key 还保留 ingress profile、request scope 和 operation，防止在不同 DNS 上下文之间复用。


## 示例

```dae
experimental {
    clash_api {
        external_controller: '127.0.0.1:9090'
        external_ui: 'zashboard'
        external_ui_download_url: 'https://example.com/dashboard.zip'
        external_ui_download_detour: proxy
        secret: 'replace-me'
        default_mode: Rule
    }
    cache_file {
        enabled: true
        path: 'cache.db'
        cache_id: 'gateway-main'
        store_fakeip: false
        store_dns: true
    }
}
```

## 相关文档

- [Clash API 参考](./api.md)
- [NFQUEUE 设计](../design/nfqueue.md)
- [全局配置参考](./global.md)
