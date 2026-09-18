# 原生 API、Clash API 与 `/stats` 参考

原生与 Clash API 具有独立的 feature、listener、凭证及 HTTP 边界，共用底层引擎 handles 与用户态统计。

## 原生 API (M1)

本节保留 M1 标题锚点，内容覆盖已交付的 M1–M6 能力（M3b 组写入除外）。以 `--features native-api` 构建并启用 [`experimental.native_api`](./experimental.md#native_api)。`--no-default-features --features native-api` 可脱离 Clash 使用。`.dae` 仍是唯一配置权威；M6 在显式授权下读取与替换已接受的源文件，不引入 SQLite 配置主存储。

固定契约为 [api-standardize cb8ac07c6520b7fb08539cc0b7701695f5a07992](https://github.com/Zakkaus/api-standardize/tree/cb8ac07c6520b7fb08539cc0b7701695f5a07992)。实现 `base` profile，不声明 `full_transparency`。Runtime、connections、flows、nodes、groups、events、出站计数与内存观测可用；history 由记录设置控制，配置与 reload operations 依赖真实启动时捕获的 `.dae` 来源。组写入、provider/geodata 管理、probe、runtime mode/settings、suspend/resume、关闭连接及其他未实现资源仍不可用，以 capabilities 为准。

| 方法 | 路径 | 含义 |
| --- | --- | --- |
| GET | `/api` | Discovery，固定 `/api/v1` base 与全部契约 links。 |
| GET | `/api/v1/version` | 原生契约身份、引擎构建版本以及构建的提交与目标平台，不伪造构建时间。 |
| GET | `/api/v1/capabilities` | 已实现资源与请求上限。 |
| GET | `/api/v1/runtime?detail=summary\|full` | 引擎 phase、已接受代次与具有独立时间戳的用户态流量。 |
| GET | `/api/v1/connections?type=all\|tcp\|udp&src=192.0.2.1&limit=100&detail=summary\|full` | 可见的活跃用户态连接；可选 `src` 必须为无端口 IP literal。 |
| GET | `/api/v1/flows`、`/api/v1/flows/{flow_id}` | 活跃及保留的终态用户态决策；detail 包含捕获的 partial trace。 |
| GET | `/api/v1/nodes` | 稳定节点 ID、当前直接成员/订阅来源与真实测量。 |
| GET | `/api/v1/groups`、`/api/v1/groups/{groupId}` | 无副作用组观测、直接成员、配置 revision/ETag 与捕获的健康数据。 |
| GET | `/api/v1/events` | 有界且需认证的 SSE，支持绑定过滤器的续传游标。 |
| GET | `/api/v1/runtime/outbounds` | 共用计数生命周期内按 `kind/name` 区分的全宽出站计数。 |
| GET | `/api/v1/runtime/memory` | 实际进程 RSS 与可读的 cgroup v2 内存事实。 |
| GET | `/api/v1/runtime/traffic/history`、`/api/v1/runtime/memory/history` | 可选 `window_seconds`、`max_points`，均默认 600、范围 1–600。 |
| GET | `/api/v1/config` | 已接受的源快照、配置 revision 与安全诊断。 |
| GET | `/api/v1/config/sources/{source_id}` | 单个已接受源的元数据及获准返回的原文。 |
| POST | `/api/v1/config/validate` | `syntax` 或离线 `full` 校验，不写盘、不 reload。 |
| PUT | `/api/v1/config/sources/{source_id}` | 强 `If-Match` 保护的单源原文替换；写盘后排队真实 reload，返回 operation。 |
| POST | `/api/v1/operations/reload` | 从磁盘重新加载，返回 daemon-owned operation；body 留空或为 `{}`。 |
| GET | `/api/v1/operations/{id}` | 真实排队、运行及终态结果。 |

Connections 的 `detail` 默认 `summary`，`type` 默认 `all`，`limit` 默认 100、范围 1–1000。拒绝重复单值或未知 query 参数。先过滤，再统计总量与应用 TCP+UDP 合计 limit；按注册观测时间降序、相同时间按 ID 字典序升序排列。total 是匹配的完整可见数量。IPv4-mapped IPv6 来源按 IPv4 比较。summary 省略 `src/dst/domain`，full 包含它们，未知 domain 为 null；full 不表示更高权限。

连接 `outbound` 是选路当时的组/动作，不是当前叶节点或重建选择。启用记录时，`flow_id`、捕获的 root-first 组/叶 ID、首次观测 UTC 与 domain 来源关联保留证据；缺失或淘汰的证据保持 unknown。逐连接 rate 与未捕获 rule ID 仍为 null。空列表是 `visibility: partial`，不代表设备没有连接。mock 数据面显示 disabled/none；未核验 hooks/policy 的真实后端显示 unknown/none，已知健康失败时可为 degraded。HTTP 就绪不等于数据面就绪。

TCP 在 copy 成功读取或 splice 成功写入目标 socket 时实时入账，成功写出的嗅探前缀仅计一次；UDP 保持原逐包语义。唯一的一秒 sampler 使用实际时间间隔；初次采样、reset 和 overflow 返回 null rate，不补零。`counter_since` 属于共用计数器生命周期，`sampled_at` 属于流量样本，`observed_at` 属于 HTTP 观察。UInt64 使用十进制字符串，有界数量仍为 JSON number。CPU 与 activation 时间仍未知；有源管理器时提供配置 revision，`last_reload` 提供最近完成的 API reload operation 结果，否则为 null。

配置 secret 后，所有 API 路径（包括 discovery/version/capabilities、禁用 action、未知 API path）都要求单个有效 Bearer header。Query token、重复凭据、错误凭据均不能回退匿名，同源 UI 也不豁免。无 secret 需显式 loopback 授权，并拒绝 `Sec-Fetch-Site: cross-site`。公共静态文件也接受 Host/Origin 校验；OPTIONS preflight 无需 bearer，但必须通过 Host、Origin、method 与 header 白名单。不返回 cookie credentials 或通配 CORS。

已知禁用 action 返回 JSON `404 capability_not_supported`，未知 path 或未定义 method 返回 JSON `404 resource_not_found`；配置来源可读但未授权写入时，PUT 返回 `403 permission_denied`。错误信封为 `{error:{code,message,details},request_id}`。HEAD 保留 GET 状态/header，无 body。API 响应带 `no-store` 与 `nosniff`。应用上限为规范化 target 4096 字节、规范化 header 名/值合计 16384 字节、body 65536 字节（含 chunked）；已认证 GET/HEAD 携带非空 body 会被拒绝。原生读取不触发 probe 或选择变化。

原生 server 最多拥有 64 条 HTTP/1.1 连接，满时暂停 accept，header 读取上限五秒；关闭时全部连接共享五秒 graceful drain，随后 abort 并逐一 join。空闲 I/O 与停滞写入分别受 30 秒期限约束；SSE heartbeat 成功写入使健康长连接保持活跃，读取不能延长阻塞 writer 的期限。TLS/HTTP2 可由可信反代终止。Forwarded headers 不改写固定 discovery path，也不授予 Host/Origin 权限。

**已记录的契约差异：** bootstrap 采用 common bearer 安全规则，尽管该 pin 的 bootstrap 标记了 `security: []`。Hyper 可在应用处理前以 400/414/431 或断连拒绝畸形/硬超限 HTTP；这些 transport 拒绝不保证 JSON 信封或应用 headers。

应用 target/header 上限作用于 Hyper **解析并规范化后的表示**，不是原始 wire 字节。Hyper 可能先移除 request-target fragment，或合并相同 `Content-Length` 字段，再交给应用计量；这些形式的原始文本即使超过应用上限，也可能得到正常响应而不是 413。原始输入仍受 Hyper 传输处理约束。这是已接受的边界差异，不另写 HTTP parser，也不宣称原始 wire 大小保证；body 限制仍覆盖全部交付的 body 字节。

配置 `ui` 后，`/` 与 `/ui` 重定向到 `/ui/`。合法的无扩展名导航可 fallback 到 `index.html`；缺失的静态资产、fonts/icons、manifest 或 service worker 返回 404，不返回 HTML。静态响应统一 `no-cache`、`nosniff`、`X-Frame-Options: DENY`，不修改 UI 自身 CSP，也不注入凭证。目录托管独立验收；不宣称已内嵌/下载 doona 或通过真实 doona/checker conformance。

### 用户态记录流（M2）

原生 listener 启用后默认记录，不依赖 dashboard 订阅。`record_flows: false` 在重启后关闭记录并释放缓冲。进程内最多保留 1024 条 flow、每条 64 steps，含 snapshot 的总保留预算 8 MiB；终态最多保留 300 秒，压力下可提前淘汰，重启清空。由既有 sampler 清理，不新增 timer。

Flow ID 表示 incarnation，不是五元组。TCP/UDP 在真实 route/sniff/verification/selected-leaf/attempt/terminal 边界捕获，拨号失败或阻断即使没有 live connection 也保留。名称、ID、代次取自决策时，不与当前选择重建关联。内核 offload 以 unknown 结束观察，不伪造连接 closed。Rule 内部执行、DNS 子步骤和底层 transport attempt 尚未完整捕获，因此 trace 为 partial，kernel/DNS scope 为 none，不开放 full_transparency。

Flow list 接受 `network/state/connection_id/detail/limit/cursor`。最多八份有界不可变 snapshot，TTL 30 秒，游标绑定 instance 与原过滤器/detail。过期列表返回 `410 snapshot_expired`，已知淘汰 ID 的有界 tombstone 返回 `410 flow_expired`，未知 ID 返回 `404 resource_not_found`；snapshot 满返回 503 与 Retry-After。Detail 不接受 query，始终返回保留的 full input/trace。计数为十进制字符串，revision/seq/elapsed_us 为 safe JSON number；不安全的可选显示字段置 null，不丢弃因果 ID 或结果。

### 节点与组（M3）

节点读取接受 `group_id`、`limit`（1–1000）及 `cursor`；只筛直接成员，不展开叶节点。节点分页最多八份 snapshot、30 秒、4 MiB，冻结分页期间观测；无效或过滤器不匹配游标返回 400。Groups 返回摘要数组，detail 的带引号 ETag 对应仅由配置决定的 revision。组 ID 为进程生命周期随机身份：同名 reload/重排保持，删除再添加获得新 ID，重启重新发现；不使用位置 UUID 或名称 hash。

Health 来自已完成且维度明确的 producer 测量，不把乐观 alive、跨族复制的排名信号、synthetic failure 或恢复延迟当真实测量。Raw TCP、HTTP 响应头、DNS exchange、QUIC handshake 保留实际目标地址族与完成时间；未知 average/ranking/warmth 保持 null/unknown。自定义组测量保留当时 member/leaf，不绑定到后来的选择。GET 不推进 URLTest、轮询或 Score 状态；尚无配置 icon 时返回 null。

M3b 的组 selection、JSON Patch 与自动策略 override 仍关闭。M6 已有无损源文件写入，但这不等于组控制已完成共同 control/reload/persistence/warm owner 集成；不能用仅改内存的 PATCH 或假中断绕过该门槛。自动策略 override 还受双网络响应契约限制。

### 原生事件（M4）

使用带 Bearer 与 `Accept: text/event-stream` 的 streaming fetch；浏览器 EventSource 不能设置所需 Authorization。可选 `kinds/flow_id` 绑定续传游标。最多保留 512 事件/60 秒，16 clients，每 client 64 条 live 队列；队满断流，不静默 skip。每 15 秒 heartbeat。Fresh 先 ready；有效续传 replay→ready→live，原子挂接不留空窗。过期、未知、旧 instance 或不同过滤器游标在 HTTP 200 前返回 `409 event_cursor_expired`。

实际发布 `stream.ready/runtime.updated/flow.updated/flow.gap/generation.changed`，配置协调器可用时还发布真实 operation 状态转换的 `operation.updated`。Generation 事件只来自已接受发布，不来自 reload 收件。事件仅含有界安全 ID/状态，不含包正文或原始配置。Flow/event 保留只在内存，不是耐久日志。

### 出站、内存与历史（M5）

`runtime/outbounds` 复用逐出站账本，不按 HTTP 客户端建立计数器。`kind` 区分 `builtin/node/group`，名称可能相同，不能只按 name 合并。累计连接、upload/download bytes 与 errors 保留完整 UInt64 十进制字符串；`active_connections` 为 safe JSON number。计数与 `counter_since` 属于共用 StatsManager 生命周期，reload 不清零。

RSS 来自 `/proc/self/status`；cgroup v2 依据实际 membership/mountinfo 定位，读取 `memory.current`、`memory.max` 与 `memory.events`。不可读取或未知的值为 null，不伪造零；`memory.max=max` 的 limit 为 null，cgroup scope 保持 unknown。Capabilities 只声明实际读到的 metric，`kernel` 为 null，不宣称内核内存核算，也不把 RSS、cgroup 和 kernel 相加。

`record_traffic` 与 `record_memory` 默认 true。两种 history 共用既有的一秒 sampler（错过 tick 使用 Skip），无客户端也记录；各最多 600 点、600 秒，仅存内存，重启清空。设 false 并重启后释放对应缓冲，history 返回 `404 capability_not_supported`，即时 runtime/outbounds/memory 仍可读。`max_points` 从最新点向前按能满足上限的最小 stride 抽取，再按时间从旧到新返回；`sampled_every_seconds` 表示该名义 stride，不保证无缺口。保留原始时间戳、null 与采样缺口，不插值或补零。

### 配置来源、校验与操作（M6）

只有真实 `.dae` 启动加载时捕获的源集合才启用配置管理；程序内构造的 Config 或 serde 格式加载不能冒充无损来源，其配置能力不可用。GET 返回最后已接受的快照，不临时重扫磁盘。源 ID 不含路径，元数据的私有路径显示为 `<redacted>`；原文 SHA-256、字节数、加载时间与逐源 `writable` 单独提供。源集合与校验最多 32 个来源、8 MiB 原始字节，依赖的每次实体化也计入数量和字节预算；geodata 文件是引擎本来就整体加载的运行时资产，只参与哈希冲突检测，不计入预算；HTTP JSON body 的 64 KiB 上限仍独立生效，超限返回 413。

默认 `config_content: false`、`config_write: false`、`writable_includes: []`，以上设置及 history 设置都需重启。Content 或 write 为 true 必须配置非空有效 bearer secret；完整正文仅供通过控制凭证认证的管理员，匿名模式不能取得。包含 API 凭据的整个源不返回 content，并且只读；不要把省略正文误当成可保存的空字符串。获准返回的 content 是逐字原文，可能含出站凭据、订阅 URL 或路径，不是沙箱化/脱敏后的保存载荷；`secrets_redacted` 不表示可以无检查地公开或回写整个响应。

启用 `config_write` 后，非凭据主文件可写；include 只有在已接受集合中，且其规范化路径相对入口目录精确匹配 `writable_includes` 时才可写。该列表不接受绝对路径、遍历或 glob，也不能授权任意新文件；generated/subscription 来源不因此可写。普通 include 仍使用原有入口相对 glob、排序、无匹配及重复/越界检查语义，不因写许可列表改变。API 禁止修改原生设置或改变、移动 API 凭据；如需编辑含凭据主文件，先在本地把凭据迁到专用只读 include 并重启，不能通过 API 完成迁移。

校验使用 `Content-Type: application/json`，例如 `{"mode":"syntax","sources":[{"id":"source-1","content":"..."}]}`；mode 可选 `syntax` 或 `full`，每个 source 的 id/path 可省略。`syntax` 只解析提交的文档，path 仅作来源标签，不授权文件访问，也不跟随磁盘 include。`full` 的首份文档对应入口主文件，额外路径须通过入口根目录授权；使用 overlay、获准本地 include、只读订阅缓存、实际本地 geodata/hosts/ECH 依赖做完整离线准入。缺失或无效依赖是错误，不联网、不创建目录或改权限、不启动 worker、不发布 generation。完成的无效 dry-run 返回 `200` 与 `valid:false`；这不代替之后真实 reload 的运行时校验，也不承诺 reload 一定成功。

PUT 的 JSON body 为 `{"content":"完整的新原文"}`。`If-Match` 必须是**单个带双引号、含 64 个小写十六进制字符的 SHA-256 强标签**，可将读取到的 `content_sha256` 加双引号使用；它比较磁盘当前原始字节，不是 config revision 或 runtime generation。源 GET 仍是 accepted 快照，因此外部编辑后可能需要本地处理或显式 reload，而不是用旧快照覆盖磁盘。

| 写入条件/结果 | HTTP 语义 |
| --- | --- |
| 缺少 `If-Match` | `428 precondition_required` |
| weak、wildcard、多个标签/重复 header、非小写 SHA-256 | `400 invalid_request` |
| 磁盘 hash 或复查的目标/依赖变化 | `412 stale_revision`，检测到的外部内容不覆盖 |
| 候选配置或依赖校验失败 | `422 unsupported_value`，不写盘、不 reload |
| 未授权源、凭据或原生设置修改 | `403 permission_denied` |
| 操作容量或协调队列繁忙 | `503 temporarily_unavailable` 与 `Retry-After` |

协调器在副作用前预留 operation，串行处理 API 新写入和 SIGHUP，SIGHUP 也先入队再读盘。单源 overlay 完整校验后，采用目录 FD、拒绝符号链接的普通文件检查、独占临时文件、保留 mode、文件 fsync、目标与完整依赖集复查、原子 rename、目录 fsync。外部编辑器不受协调器约束，最后检查到 rename 之间仍有竞争窗口；UI 保存期间不要并行手工改同一文件。Rename 后若目录 fsync 失败，错误明确携带 `written:true,durability_confirmed:false`：可见内容已经改变，不表示未写或回滚。

PUT 仅在耐久写入并进入真实 reload 队列后返回 `202`；显式 POST reload 入协调队列后返回 `202`。响应含 `operation_id`、`href`、相同的 `Location` 与 `Retry-After: 1`，不表示配置已经生效。操作由 daemon 持有，HTTP 断连不取消它或其 supervisor reconciliation。可选 `Idempotency-Key` 绑定 principal、method、path、instance 与原始 body：同 key 同 body 的并发/重试共用结果，不重复写入或 reload，丢失首个 202 后仍可用原 If-Match 重试；不同 body 返回 `409 idempotency_conflict`。总共最多 32 个预留/保留操作，终态保留 300 秒，未过期记录不因容量提前淘汰；重启后不保留。

通过 GET operation、`runtime.last_reload` 及 `operation.updated` 读取真实结果，不能把收到 202 当作 succeeded。Reload 拒绝时保留旧 accepted 快照和 generation，但已写入字节不回滚；提交后 degraded 时保留新快照/generation 并报告 failed，而不是声称旧代仍活动。管理员应据磁盘内容与结果修复，再显式 reload。SIGHUP 本身不创建 API operation。仅改注释也会更新 source hash/config revision，但有效配置未变时不增加 runtime generation；有效组成员变化会改变 revision，健康测量变化不会。这三种版本不是可互换的并发令牌。

## 启用与鉴权

仅当 `experimental.clash_api.external_controller` 非空，且二进制文件包含默认启用的 `clash-api` 特性时，API 服务才会启动。控制器地址必须是 `127.0.0.1:9090` 或 `[::1]:9090` 这样的数字套接字地址，不能使用 DNS 主机名；`:port` 会绑定 `0.0.0.0:port`。无效地址只会写入日志，不会停止引擎。

当 `experimental.clash_api.secret` 非空时，API 请求必须携带：

```http
Authorization: Bearer <secret>
```

WebSocket upgrade 也可以改用 `?token=<percent-encoded-secret>`。honk 会先对 token 做 percent-decode，再进行精确比较。query token 鉴权仅适用于 WebSocket upgrade；普通 HTTP 请求使用 Bearer header。`secret` 为空时关闭鉴权。`/ui` 静态目录位于 API 鉴权 layer 之外。

**API 自身不提供 TLS。** 应将其绑定到 localhost，或在前方部署 TLS reverse proxy；当不可信客户端能够访问 listener 时，必须设置强 `secret`。

随附的 `config.dae` 绑定 `127.0.0.1:9090`。非回环控制器地址配合空 `secret` 时，启动会发出警告，但仍允许监听；无论是否配置防火墙，通配地址和已分配的接口地址都适用。

## 端点表

下表与 `crates/honk-core/src/clash_api.rs` 中的 router 一致。

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| GET | `/` | 返回 Clash hello 文档；启用外部 UI hosting 时，将非 JSON 客户端重定向到 `/ui/`。 |
| GET | `/version` | 返回 `honk <build-version>`（包含发布 tag，与 CLI 共用构建版本）及 Clash premium/meta capability flag。 |
| GET | `/configs` | 返回当前模式、已实现的 Clash 兼容配置快照，以及 `honk-diagnostics` 下当前配置的安全诊断。 |
| PUT | `/configs` | 兼容性 no-op；接受请求并返回 `204 No Content`。 |
| PATCH | `/configs` | 将 `mode` 设为 `Rule`、`Global` 或 `Direct`；匹配不区分大小写。 |
| GET | `/proxies` | 返回所有节点和组，以及合成的 `GLOBAL` Selector。 |
| GET | `/proxies/{name}` | 返回一个节点、组或 `GLOBAL` Selector。 |
| PUT | `/proxies/{name}` | 用 `{"name":"member"}` 选择 Selector 组的直接成员；也可修改合成的 `GLOBAL` Selector。包括 Score 在内的自动组会拒绝写入。 |
| GET | `/proxies/{name}/delay` | 使用调用方的 `?url=`，对节点或组执行按需代理延迟测试。已预热的传输会复用；每个尚未预热的可复用会话或 QUIC 客户端都会先在临时运行时中预热，再开始计时。 |
| GET | `/group/{name}/delay` | 使用调用方的 `?url=` 测试全部组成员，最多并发 `URLTEST_MAX_CONCURRENT`（10）次代理拨号，并以相同计时语义返回成功成员的延迟。 |
| GET | `/rules` | 每条路由返回一行。简单 matcher 使用原生 Clash rule type；组合、取反和 `must` 规则使用 `complex`，并保留完整 dae 语句。 |
| GET | `/connections` | 返回连接快照；WebSocket upgrade 后改为推送快照。 |
| DELETE | `/connections` | 关闭所有已跟踪连接。 |
| DELETE | `/connections/{id}` | 关闭一个已跟踪连接。 |
| GET | `/traffic` | 通过 WebSocket 或分块 JSON 行推送每秒流量。 |
| GET | `/memory` | 通过 WebSocket 或分块 JSON 行推送进程 RSS。 |
| GET | `/stats` | 返回下文所述的用户态出站、ready pool、热资源、Score 选路原因和 UDP 快照。 |
| GET | `/logs` | 通过 WebSocket 或分块 JSON 行推送 tracing 事件；所有订阅者共用一个 256 槽位的广播队列，`?level=` 默认为 `info`。 |
| GET | `/dns/query` | 经 honk DNS 解析 `?name=` 并返回 DoH 风格 JSON；`?type=` 默认为 `A`。 |
| POST | `/cache/fakeip/flush` | cache database 存在时，清除持久化的 FakeIP 前缀条目。 |
| POST | `/cache/dns/flush` | 清除存活 DNS cache 及其持久化 DNS 状态。 |
| GET | `/providers/proxies` | 将非空组暴露为 Clash proxy provider。 |
| GET | `/providers/rules` | 返回当前空桩文档 `{"providers":[]}`。 |
| GET | `/ui`, `/ui/*` | 将 `/ui` 重定向到 `/ui/`，并提供已配置的外部 UI 目录。 |

对普通 HTTP GET，`/traffic`、`/memory` 和 `/logs` 每行发送一个 JSON 文档。`/logs` 只在存在订阅者时启用动态 `tracing` 事件过滤；无订阅者时，Clash 日志层不格式化事件。每个订阅者的级别过滤发生在共享队列之后。订阅者落后时会跳过被覆盖的事件，且不会收到事件丢失标记。

### `/configs` 中的诊断信息

`GET /configs` 保留现有 Clash 字段，并新增 `honk-diagnostics`。
配置项和诊断信息来自同一份已提交的配置快照。启动时只发布通过准入检查的
文件和订阅诊断。重载失败或订阅刷新被拒绝时，当前诊断列表保持不变；
接口不缓存最近一次失败尝试。

有效配置未变的成功重载可以替换诊断信息而不递增 `generation`。订阅刷新通过授权和
准入检查后，只替换该订阅的诊断，即使节点未变也是如此；
静态文件和其他订阅的诊断保持不变。

库调用方须向 `ControlPlane::reload_runtime_config(config, diagnostics)` 传入 `DiagnosticBuckets`，分别保留静态配置与订阅正文的诊断；没有诊断的程序构造输入使用 `DiagnosticBuckets::default()`。`merge_subscription_nodes(provider, nodes, diagnostics)` 接收该订阅的诊断向量，也支持已准入但没有 worker 声明的订阅。完整配置替换会移入候选配置的全部诊断来源信息，订阅替换只影响对应订阅。SIGHUP 仅保留重建候选配置时实际沿用的订阅正文的诊断；自动生成的拓扑/ECS 更新保留原输入来源。所有修改沿用配置写锁的发布屏障，先获取配置锁，再获取诊断锁。

完整替换载荷中的 provider bucket 必须使用唯一 UUID。重复 UUID 会在发布前拒绝整个重载，即使有效配置未变也是如此；当前配置与诊断保持不变。

| 字段 | 含义 |
| --- | --- |
| `honk-diagnostics.generation` | 当前配置的 `generation`；启动时为 `0`。 |
| `honk-diagnostics.sources` | 保留的诊断所引用的来源及这些来源的祖先，仅包含元数据。 |
| `sources[].id` | 本次快照内的不透明数字来源标识，供 `diagnostics[].source` 引用。 |
| `sources[].ordinal` | 来源在单次解析尝试的来源表中的原始序号，从 `0` 开始。 |
| `sources[].parent` | 父来源的 `id`；根来源为 `null`。 |
| `honk-diagnostics.diagnostics` | 当前配置和已准入订阅保留的安全诊断。 |
| `diagnostics[].code` | 稳定的诊断代码。 |
| `diagnostics[].severity` | 小写严重级别：`info`、`warning` 或 `error`。 |
| `diagnostics[].source` | 对应的 `sources[].id`。 |
| `diagnostics[].span` | 从 `0` 开始的字节范围 `{start, end}`，不含 `end`；未知时为 `null`。 |
| `diagnostics[].line` | 原始文本中的行号；未知时为 `null`。 |
| `diagnostics[].byte_column` | 按字节计数的列号；未知时为 `null`。 |
| `diagnostics[].setting` | 含原始条目序号的固定配置字段路径，不含用户提供的名称。 |
| `diagnostics[].value` | 安全值表示；私有值经过脱敏。 |
| `diagnostics[].message` | 静态诊断消息。 |
| `diagnostics[].entry_index` | 原始条目序号；未知时为 `null`。 |
| `diagnostics[].related_indices` | 相关原始条目的序号。 |
| `diagnostics[].terminal` | 该诊断是否表示本次尝试的终止错误。 |

配置的 `generation` 与当前 DNS 运行时一致。来源标识仅在本次快照内有效，不是文件系统标识。
来源先按静态文件、再按配置中的订阅声明顺序排列，最后按保留 bucket 的顺序列出已准入的非 worker 订阅；各来源表保留原始顺序。
仅列出诊断引用的来源及其祖先，不导出文件路径、原始输入、凭据、订阅名称或订阅 ID。

### 延迟测量

调用方通过 `?url=` 指定测试 URL。组请求最多同时执行 `URLTEST_MAX_CONCURRENT`（10）项经代理的测量。

延迟测试使用规范的 HTTP 检查目标解码器：HEAD 保留原始路径与查询串（包括点段和仅查询串的 `/?query`），authority 移除凭据和默认端口，fragment 不会发送。它与周期健康检查共享 HTTP 实现，报告第二轮请求的热路径 RTT，不含代理拨号、目标 TLS 与第一轮请求。HTTPS 验证证书，协商 HTTP/2 或 HTTP/1.1，并禁用 server push。两轮最终响应的解码状态都必须为有效的 200–499。第二轮传输失败或超时可回退到已验证的第一轮样本；HTTP/1 部分响应即使超时也不回退，而正常 HTTP/2 GOAWAY 可以回退。每轮 HTTP/1 临时响应头与最终响应头的累计上限为 16 KiB，H2 响应头列表上限同样为 16 KiB。session 预热、拨号、目标 TLS、H2 启动与每轮请求分别使用阶段预算。冷可复用 generation 探测使用带 guard 的临时 runtime，结束后关闭；HTTP/2 driver 在完成或取消后释放，因此组扫描不会为每个已测试节点留下新的常驻可复用 runtime。

已知限制：[`h2` 0.4.19 可能把缺少 `:status` 的响应报告为 200](https://github.com/hyperium/h2/issues/958)，因此这种畸形 HTTP/2 响应仍可能得到成功的延迟结果。该依赖修复已明确延期，等待上游处理，不使用本地 fork/vendor 补丁。

成功测量会更新节点延迟历史。单节点失败返回 `503`；组测量会省略失败成员；两者都会追加供 URLTest 选择使用的 failure strike。

每次经代理或内建 `direct` 叶节点执行、并实际经过 Score 组的 delay-test exchange，都会把真实 URL 目标及成功或失败反馈给包含该被测叶节点的每个 Score 组。之前仅连接 server/session 的预热只报告聚合 setup，不会把该 URL 虚构为预热自身的目标；非 Score 路径不会创建 reporter 或评分 cell。

### Score 组表示

配置为 `policy: score` 的组始终可用，并为兼容 Clash 表示成 `type: "url_test"`。其 `all` 列表与其他组一样保留直接成员 tag，`now` 则报告当前聚合 TCP 胜者，而不是泄露某个精确目标的私有选择。Score 始终保持自动且权威：`PUT /proxies/{name}` 会被拒绝，不会固定成员。评分 cell 与仅由 scorer 持有的目标数据不会新增到 proxy 文档；`/stats.score` 只包含下文的安全聚合计数。`/connections` 只保留原有的目标元数据。

## 模式与 Selector 修改

`PATCH /configs` 接受如下 JSON 对象：

```json
{"mode":"Global"}
```

模式更新经过 `DatapathFlagsHandle`；它是 shared mode 与 `DATAPATH_FLAGS_MAP` 唯一的串行化 writer。因此模式修改会与 reload 的 NFQUEUE fence、reopen 和 disable 操作原子组合，不会重新发布过期的 readiness bit。规则派生的 feature bit 属于不可变的路由 policy descriptor。启用 cache database 时会保存规范化后的模式。

`PUT /proxies/{name}` 不要求特定 `Content-Type`。对已配置的 Selector 组，目标必须是直接成员 tag；只能经嵌套组到达的叶节点并非直接成员。选择确实发生变化时会调用 group manager 的 cache callback，因此启用 `cache_file` 后会把选择持久化到 `cache.db`。若该组设置了 `interrupt_connections`，honk 会移除与该组、其成员 tag 及可达叶节点关联的已跟踪连接，使后续流量通过新选择重新拨号。写入已有选择不会触发操作。URLTest、LoadBalance、Fallback 及 Score 组都会拒绝该修改。

`GLOBAL` 是合成 Selector，但其 `all` 中每个成员都是具体的已配置组或节点，并有对应的顶层 proxy 文档。`PUT /proxies/GLOBAL` 只接受其中的名称，并通过同一个 `DatapathFlagsHandle` 更新；启用 cache database 时以 `GLOBAL` Selector key 保存。空值、已移除、未知及旧虚拟选择都会回退到第一个具体成员。

## 外部 UI hosting

设置 `experimental.clash_api.external_ui` 以提供静态 dashboard 目录。目录缺失或为空时，honk 会在后台下载 ZIP；启动不会等待，文件可用前静态路由返回 `404`。`external_ui_download_url` 会替换内建 zashboard URL，`HONK_UI_DOWNLOAD_URL` 则保持最高覆盖优先级。

每次下载请求（含重定向）只接受 HTTP(S)，最多跟随五次重定向，下载的 ZIP 正文上限为 128 MiB。允许 HTTPS 降级到 HTTP，也允许 URL 直接使用 IP 地址；每一跳仍遵循路由或指定的 `external_ui_download_detour`。

非空 `external_ui_download_detour` 会强制初始请求和 redirect 都经过该节点或组。该字段为空时，每个 URL 遵循 honk 当前的流量路由决策：`direct` 使用直连 HTTP client，`block` 中止下载，proxy 结果使用选中的出站叶节点。每次直连或经代理且实际经过 Score 组的 HTTP exchange，都会向路径经过的 Score 组报告真实 host/IP、端口、setup、首响应、字节与终态；其他路径不创建评分 reporter 或 cell。下载或解压失败只写日志，不会停止引擎。

## `GET /stats`

`GET /stats` 是用户态快照，而不是 eBPF `OUTBOUND_STATS` map，也不暴露该 map 的报文 counter。固定 TCP、UDP 和 NFQUEUE schema 不创建动态的逐节点 label。

```text
{
  outbounds: [{ name, totalConns, activeConns, upload, download, errors }],
  pool: { readyHits, readyMisses, entries },
  quic: {
    activeConnections, srttUs, cwndBytes, flowReceivedBytes, flowSentBytes,
    receiveWindowBytes, receiveWindowAvailableBytes, streamReceiveWindowBytes,
    sendWindowBytes, sendWindowAvailableBytes, lossRatePpm, sentPackets,
    ackFrames, lostPackets,
    sentPlpmtudProbes, lostPlpmtudProbes, currentMtu, blackHoles,
    congestionEvents, txBytes, rxBytes, txDatagrams, rxDatagrams, txIos, rxIos,
    transportTxWouldBlock, transportTxDrops, transportRxDrops, sessionRxDrops,
    sendTimeouts, pathStalls
  },
  warm: {
    nodes: { preconnect, health, udp, selector, traffic },
    sessions: { anytls, vless, tuic, juicity, hysteria2 }
  },
  tcp: {
    activeFlows, limit, capacity: { rejected }
  },
  score: {
    groups: [{ name, tcp: R, udp: R }],
    cache: { exactCells, aggregateCells, exactEvictions, aggregateEvictions }
  },
  udp: {
    endpoint: { hits, misses },
    latency: {
      route: H, dial: H, replyReady: H, firstSend: H, firstReply: H
    },
    capacity: { rejected },
    slowPermit: { accepted, rejected, closed },
    queue: { accepted, full, flowFull, globalPayloadFull, closed },
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
}
H = { count, sumNanos, buckets }  // buckets has 64 fixed log2 slots
R = {
  coldExplore, periodicExplore, reliabilityWinner, performanceWinner,
  incumbentHeld, freshFailureBypass, deadFiltered, switchFlap,
  failStreakExcluded, exploreBackedOff
} // R 的每个值均为 u64 计数
```

### TCP 字段

| 字段 | 含义 |
| --- | --- |
| `activeFlows` | 当前持有 TCP admission permit 的透明 TCP 流。 |
| `limit` | 当前进程级 TCP 流准入上限；从描述符导出的 floor 开始，并随空闲描述符余量动态扩缩。 |
| `capacity.rejected` | 因 TCP 预算已满而等待 permit 的 accept-loop 单调计数；accepted socket 保留在内核 backlog 中，不会被丢弃。 |

### QUIC 字段

`srttUs`、`cwndBytes`、`currentMtu`、`receiveWindowBytes`、`receiveWindowAvailableBytes`、`streamReceiveWindowBytes`、`sendWindowBytes` 和 `sendWindowAvailableBytes` 是活动连接的平均值；没有活动连接时为零。`flowReceivedBytes` 统计已交付给应用的 stream 字节，`flowSentBytes` 统计已被对端确认的 stream 字节；与报文、UDP 字节、I/O、丢包、黑洞和拥塞计数一样，它们包含已完成的池化连接。

池化 TUIC、Juicity 与 Hysteria2 连接每秒采样一次 flow-control 状态。收发方向的十秒 goodput EWMA 必须在 RTT 至少 80 ms 且连续三个样本确认高 BDP 后，才会把 connection 接收或发送 floor 提高到约 `2 x BDP`。peer 发来的 `DATA_BLOCKED` / `STREAM_DATA_BLOCKED` 是窗口成为瓶颈的直接证据：不受 RTT 门限限制，直接把 connection 或 stream 接收 floor 加倍——窗口压流时 goodput 估计值本身也被压扁，无法用作升档依据。零进展样本只有在对应 connection credit 仍受压时才会保留但不推进 streak。每个 floor 独立执行五分钟升档冷却，自动升档最大为 32 MiB，但不会降低更大的显式配置。honk 不会因应用需求低而缩小已学习窗口，也不会热切换拥塞控制。

`ackFrames` 统计收到的 ACK frame，是路径进度信号；重复 ACK frame 可能被重复计数。`lossRatePpm` 排除 PLPMTUD 探测：分母为 `sentPackets - sentPlpmtudProbes`，而 `lostPackets` 同样不包含探测丢包。`sentPlpmtudProbes` 与 `lostPlpmtudProbes` 单独暴露探测计数。`txIos` 与 `rxIos` 表示批处理效率。`transportTxWouldBlock` 统计满载的 64 包 adapter 队列（Quinn 会重试）；底层代理报告拥塞或超时后主动丢弃的报文计入 `transportTxDrops`；满载的 adapter 接收队列计入 `transportRxDrops`，满载的 TUIC/Hysteria2 256 包会话队列计入 `sessionRxDrops`。`sendTimeouts` 与 `pathStalls` 是进程生命周期内的恢复事件。

### Score 选路原因字段

`score.groups` 是经鉴权 `/stats` 响应中的附加部分。当前没有任何组使用 `policy: score` 时它为 `[]`；否则它包含每个当前 Score 组（包括没有解析出叶节点的组），按 `name` 的字典序排列。每组始终都有 `tcp` 和 `udp` 对象，且每个对象始终包含全部 `R` 字段；没有网络活动时以零表示，绝不省略字段。

每个值都是饱和的 `u64` 计数，不是延迟、字节、时长、目标或健康度量。前六个字段按固定优先级分类一次已授权的多候选 Score **Apply**：初始预算探索为 `coldExplore`；周期上置信界非现任为 `periodicExplore`；成功保持现任为 `incumbentHeld`；只有新鲜失败证据打破已训练且效用差距很小的保持条件时为 `freshFailureBypass`；所有备选均在所选可靠性带之外时为 `reliabilityWinner`；其余为 `performanceWinner`。`deadFiltered` 独立计数活性过滤移除的唯一叶候选。`switchFlap` 独立计数已提交胜者在八次选择内切回前一胜者；有意的冷探索和周期探索不改变这段后悔窗口。`failStreakExcluded` 按每次已授权 rank 累计被三连败新鲜失败门排除的候选数，`exploreBackedOff` 累计当前处于探索退避的候选数。Peek、`/proxies`、`/stats`、单例旁路和最后尝试选择均不计数。

计数在进程启动时从零开始，只在进程内存中累积。只要组名仍在已提交配置中，成功 reload 会保留它们，包括零叶节点以及临时 Score→非 Score→Score 转换；非 Score 组不会显示在此响应中。已提交的删除会清除该名称的计数，之后重新创建同名组从零开始。受 generation fence 约束的已淘汰 manager 在被替换后不能再修改计数，即使同名组随后被重新创建。快照在 JSON 序列化前复制，读取不会改变选路状态。

`/stats.score` 只公开组名和 TCP/UDP 的二十个聚合计数，外加一个 `cache` 对象，给出两个 4,096 项证据 LRU 的当前 cell 数（`exactCells`、`aggregateCells`）与累计淘汰数（`exactEvictions`、`aggregateEvictions`）。它绝不包含节点、节点 ID/tag、目标/domain/IP/port、目标地址族、评分 cell、cadence 键、manager authority、凭据或其他 scorer 私有值；这些值也不会进入新的 Score 日志或持久化。此新增内容不改变 `/proxies` 或 `/stats.outbounds` 中既有的节点名，也不改变 `/connections` 中既有的目标元数据。

### 出站与 ready pool 字段

| 字段 | 含义 |
| --- | --- |
| `outbounds[].name` | 出站名称。 |
| `outbounds[].totalConns` | 经该出站启动的连接数。 |
| `outbounds[].activeConns` | 当前经该出站打开的连接数。 |
| `outbounds[].upload` | 用户态中从客户端到 proxy 的字节数。 |
| `outbounds[].download` | 用户态中从 proxy 到客户端的字节数。 |
| `outbounds[].errors` | 归因于该出站的连接尝试失败数。 |
| `pool.readyHits` | ready 裸连接 pool 命中数。 |
| `pool.readyMisses` | ready 裸连接 pool 未命中数。 |
| `pool.entries` | 当前 ready 裸连接条目数。 |

### Histogram 格式

每个 `H` 都是 `{count, sumNanos, buckets}`。`count` 是观测数，`sumNanos` 是以纳秒计的总和。`buckets` 是包含 64 个非累积计数的数组：slot $n$ 覆盖 $2^n$ 到 $2^{n+1}-1$ ns，slot 0 还包含零，最后一个 slot 在 `u64::MAX` 饱和。

### UDP 字段

| 字段 | 含义 |
| --- | --- |
| `endpoint.hits` | 已建立 UDP endpoint fast path 处理的报文数。 |
| `endpoint.misses` | cold flow 的 endpoint lookup miss 数。 |
| `latency.route` | cold route selection 延迟。 |
| `latency.dial` | cold UDP dial attempt 延迟。 |
| `latency.replyReady` | endpoint driver commit 前同步准备 reply socket 的延迟。 |
| `latency.firstSend` | 首次发送尝试延迟。 |
| `latency.firstReply` | 首个应答成功重新注入客户端之前的时间。 |
| `capacity.rejected` | 精确 endpoint capacity reservation 被拒次数。 |
| `slowPermit.accepted` | 进入活动 UDP slow path 的 admission 数。 |
| `slowPermit.rejected` | 因 shared connection semaphore 已满而拒绝的 slow-path admission 数。 |
| `slowPermit.closed` | generation draining 期间拒绝的 slow-path admission 数。 |
| `queue.accepted` | 进入有界 endpoint-driver queue 的报文数。 |
| `queue.full` | retained queue 的 drop-newest 事件总数。 |
| `queue.flowFull` | 单 flow packet slot 上限导致的 drop-newest 数。 |
| `queue.globalPayloadFull` | 全局 retained payload byte 上限导致的 drop-newest 数。 |
| `queue.closed` | 对正在关闭或已关闭 endpoint driver 发起的 queue 尝试数。 |
| `firstSend.failures` | 首次发送错误或超时数；两者都按 ambiguous send 处理。 |
| `stagger.attempts` | 已启动的 cold URLTest speculative preparation 尝试数。 |
| `stagger.winners` | 首个满足条件且成功的 staggered preparation 数。 |
| `stagger.cancellations` | 其他 candidate 获胜后取消的已启动 speculative preparation 数。 |
| `warm.attempts` | 已启动的 generation-owned UDP warm dispatch 数。 |
| `warm.successes` | 返回 `Ready` 的 warm dispatch 数。 |
| `warm.failures` | generation 仍存活时的真实 warm failure 数。`NotApplicable` 保持中性。 |

`queue` 衡量 endpoint-driver queue；它不同于衡量 UDP slow path admission 的 `slowPermit`。

### NFQUEUE 字段

| 字段 | 含义 |
| --- | --- |
| `received` | NFQUEUE listener 投递的报文数。 |
| `activeFlows` | 当前由 pending-verdict correlator 持有的 flow cell 数。 |
| `kernelQueueDepth` | 当前活动 kernel queue 实例中的排队报文数。 |
| `kernelStatsAvailable` | 最近一次 kernel queue statistics 读取是否成功。 |
| `kernelStatsReadErrors` | 累计 kernel queue statistics 读取失败数。 |
| `kernelDropped` | 因 kernel NFQUEUE 达到 queue 上限而丢弃的报文数；跨 queue hard rebind 累加为进程生命周期 counter。 |
| `kernelUserDropped` | kernel 向用户态投递 NFQUEUE message 时丢弃的报文数；跨 queue hard rebind 累加为进程生命周期 counter。 |
| `heldPackets` | 当前已投递但 verdict guard 仍被持有的报文数。 |
| `heldPeak` | queue service 报告的同时持有 verdict guard 峰值。 |
| `socketReceiveBufferBytes` | netlink socket 的有效接收 buffer 大小。 |
| `actorQueueFull` | 因有界 ingest actor queue 已满而 fail-closed 丢弃的报文数。 |
| `correlatorFull` | 达到任一 correlator 硬上限时丢弃的报文数：4,096 个 flow cell 或每流 64 个 retained verdict。 |
| `actorQueueDepth` | 当前 ingest actor queue 条目数。 |
| `actorQueuedBytes` | 当前 ingest actor queue 保留的 payload 字节数。 |
| `actorOldestAgeNanos` | 当前最老 ingest actor 条目的年龄，单位为纳秒。 |
| `directAccepted` | direct 决策成功执行 marked `NF_ACCEPT` verdict 的次数。 |
| `proxyCopied` | payload 所有权转交给规范 UDP 初始化器的次数。 |
| `proxyDropped` | proxy 决策成功对原始报文执行 `NF_DROP` verdict 的次数。 |
| `block` | policy block 成功执行 drop verdict 的次数。 |
| `cancel` | cancellation 成功执行 drop verdict 的次数。 |
| `drop` | 其他成功执行的 fail-closed drop verdict 数。 |
| `tokenMismatch` | 过期或不匹配的 decision token/flow identity 事件数。 |
| `tokenExhaustion` | 观测到持久化 decision-token allocator 耗尽的次数。 |
| `tokenRollovers` | token 耗尽后成功进行 generation rotation 的次数。 |
| `verdictErrors` | `NF_ACCEPT` 或 `NF_DROP` 操作失败数。 |
| `receiptToVerdict` | 从 listener 收包到成功 terminal verdict 的 histogram；它不是 kernel queue residence time。 |

独立的一秒 sampler 读取自有 kernel queue，不依赖报文 dispatch。读取失败后，先前的 `kernelQueueDepth`、`kernelDropped` 和 `kernelUserDropped` 仍保持可见，而本地 held-packet 与 receive-buffer gauge 继续刷新。

### 热资源字段

| 字段 | 含义 |
| --- | --- |
| `warm.nodes.preconnect` | 归因于启动时裸 TCP preconnect 的热节点。 |
| `warm.nodes.health` | health probing 期间观测到的热节点。 |
| `warm.nodes.udp` | 归因于 UDP warm coordinator 的热节点。 |
| `warm.nodes.selector` | 作为已配置 Selector 叶节点而保留的热节点。 |
| `warm.nodes.traffic` | 没有显式 attribution mark、因而归因于 traffic 的热节点。 |
| `warm.sessions.anytls` | 保留的 AnyTLS pool session 数。 |
| `warm.sessions.vless` | 保留的 VLESS pool session 数。 |
| `warm.sessions.tuic` | 已占用的 TUIC client slot 数。 |
| `warm.sessions.juicity` | 已占用的 Juicity client slot 数。 |
| `warm.sessions.hysteria2` | 已占用的 Hysteria2 client slot 数。 |

一个节点可以同时计入多个显式原因。gauge 跟随当前 runtime generation；已排干资源会从下一次快照中消失。

## Related docs

- [Experimental 配置](./experimental.md)
- [NFQUEUE 设计](../design/nfqueue.md)
- [控制面设计](../design/control-plane.md)
