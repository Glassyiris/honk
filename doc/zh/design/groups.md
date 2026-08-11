# 组选择、健康检查与预热设计

本文说明 honk 如何把组解析为叶子出站、跟踪其健康状态，并以有界方式保留预热资源。

## 范围

本文覆盖 `GroupManager`、`AliveDialerSet`、冷启动 URLTest 准备流程与预热资源 coordinator。组字段和策略语法见[组参考](../reference/groups.md)；进程级健康检查、预热与拨号配置键见[全局参考](../reference/global.md)。

## 组管理器与选择流水线

`SharedGroupManager` 是稳定且可热切换的句柄：

`Arc<parking_lot::RwLock<Arc<GroupManager>>>`

重载会构建完整的替代 `GroupManager`，迁移组和成员 tag 仍然存在的 Selector 选择，安装回调，再切换内部 `Arc`。因此读者只会看到旧管理器或新管理器，不会看到构建到一半的组图。

facade 与内部实现按职责拆分：

| 模块 | 职责 |
| --- | --- |
| `mod.rs` | `GroupManager` 类型、共享句柄与选择计划入口 |
| `resolver.rs` | 嵌套组展开、成员/叶节点内省、环切断与 Selector 选择迁移 |
| `filter.rs` | 按网络和地址族过滤存活性 |
| `policy.rs` | Selector、URLTest、LoadBalance、Fallback 选择与延迟排名 |
| `state.rs` | URLTest/Fallback 缓存、Selector 选择、空闲时间戳与回调 |

选择遵循一个不变量：完成解析和存活性过滤后，拨号路径只使用策略选出的结果。Selector 返回其有效手动选择，URLTest 返回当前胜者，LoadBalance 返回下一个成员，Fallback 返回固定成员。唯一的多候选例外是尚无测量值的顶层 URLTest 组；已有测量值的 URLTest 和所有非 URLTest 计划都是权威的单叶节点计划。

## 策略语义

| 策略 | 运行时行为 |
| --- | --- |
| Selector | 运行时选择优先，其次是 `default`，最后是第一个合格成员。Clash API 修改运行时选择。`PersistCallback` 把有效写入持久化到 `cache.db`；启用 `interrupt_connections` 时，`InterruptCallback` 关闭该组已跟踪的连接。已配置但不健康的选择仍保有预热所有权，即使流量暂时选择另一个合格成员。 |
| URLTest | 选择最小减半递推移动平均，分别保存 TCP 与 UDP 选择，应用 tolerance 滞后，并在拨号和选择查询时惰性重算。真实选择变化可以调用 `InterruptCallback`。 |
| LoadBalance | 按声明顺序轮询合格成员。每个组分别为 TCP 和 UDP 持有独立 `AtomicUsize` 游标。轮转从不调用 `InterruptCallback`。 |
| Fallback | 分别为 TCP 和 UDP 固定声明顺序中的第一个合格成员。该成员死亡前保持固定；更靠前的成员恢复不会触发 failback。 |

### URLTest 排名与滞后

延迟采用减半递推移动平均：

`next = (previous + sample) / 2`

第一个样本初始化平均值。这就是 dae `min_moving_avg` 语义：近期变化能较快生效，同时不让单次抖动成为权威值。

`SelectionNetwork::Tcp` 与 `SelectionNetwork::Udp` 分别保留胜者。TCP 使用 TCP 探测平均值；若组配置了自定义目标，则使用 `(member tag, check_url)` 平均值。UDP 先使用 `DataUdp`，再使用 `DnsUdp`；如果所有合格候选都没有 UDP 测量数据，则镜像 TCP 选择，而不是用缺失数据虚构 UDP 排名。因此有效回退顺序是 `DataUdp → DnsUdp → TCP`。

有效 tolerance 为 `max(配置值, 1 ms)`。满足下式时继续保留当前选择：

`best latency + tolerance >= incumbent current measured latency`

当前选择的基线在每次选择时重新读取，而不是保留它胜出时的旧值。因此已退化的当前节点可以被替换；这与 sing-box `Select()` 行为一致。

一次拨号失败会清除该节点的延迟历史，并插入一个 10 秒合成罚样本。下一次拨号会立即重算，同时后续一个快速样本不能让不稳定节点立刻回到第一名。

组的 `check_url` 会建立独立的 TCP-only 存活性和延迟状态，键为 `(member tag, check_url)`。失败只会从使用该目标的组中排除该成员。Selector 组忽略 `check_url` 并打印告警。URLTest 在超过 `idle_timeout` 后暂停探测；未设置时使用健康层默认的 30 分钟，下一次真实选择会立即唤醒探测。

## 嵌套组与成员身份

`Group.groups` 指定子组。每个子组只贡献一个候选：该子组自己的策略针对当前网络和地址族选出的叶节点。父组把它作为一个成员进行排名或固定，而不是把所有后代合并进父策略。

解析受 `MAX_GROUP_DEPTH = 8` 和每次遍历的 visited set 限制。构造阶段还会对组边执行 DFS，并切断每条闭环边，同时打印告警。这些检查可防止异常组图卡住选择或内省。

即使物理拨号落到更深的叶节点，身份仍然是成员 tag：

| API | 返回的身份 |
| --- | --- |
| `node_names_in_group` | 直接节点 tag 加子组 tag |
| `leaf_node_names_in_group` | 该组下可达且去重的真实叶节点 |
| `delay_test_members` | 每个有效成员一个 `(member tag, current leaf)` 对 |
| `selection_chain` | 从组经已选子组到叶节点的当前链 |

自定义 URL 探测会在每个周期重新解析 `delay_test_members`。子组通过其当前选择接受探测，但结果记录在子组 tag 下。因此父组把子组视为一个稳定成员，符合 sing-box RealTag 语义。

## 冷启动 URLTest UDP 准备

只有没有可用测量值的顶层 URLTest 计划可以准备多个 UDP transport。候选按绝对偏移 `0 ms`、`30 ms`、`80 ms` 启动，之后每隔 `80 ms` 启动一个；同时最多有三个准备任务。绝对调度可避免较早的慢任务推迟所有后续启动时间。

第一个成功且仍然合格的候选获胜。honk 在把胜者绑定到 endpoint 前中止并排空所有已启动 loser，重新检查胜者是否合格，然后在 endpoint 发布或发送第一个应用报文前提交协议状态。

只有已观察到的准备 `Err` 会影响流量健康。未启动任务、取消、已变为不合格的成功结果以及成功排空的 loser 都是中性的；排空时发现的已完成错误仍属于已观察错误并会计数。AnyTLS 使用调用者所有的 provisional pool slot，因此 loser 不会发布 session。QUIC 协议构建 detached client，只发布最终胜者；loser client 与其推测任务一起关闭。

## 健康状态与探测

`AliveDialerSet` 使用节点 `NodeId` UUID 作为节点健康状态、注册、历史、紧急触发器与延迟集合的键。显示名只用于日志和探测查找，不是身份。每个节点有六个独立状态：三个域分别覆盖 IPv4 与 IPv6。

| 失败来源 | `Tcp` | `DnsUdp` | `DataUdp` |
| --- | ---: | ---: | ---: |
| 周期探测 | 1 | 3 | 3 |
| 真实流量 | 10 | 3 | 50 |

探测失败与流量失败使用独立计数器。探测失败应用从 5 秒到 300 秒的指数冷却。另一个 `min(5s, check_interval)` 恢复调度器只检查冷却已到期的死亡域/地址族状态；深度退避状态仍以 300 秒节奏继续探测，不会永久停止。

死亡状态通常需要连续两次探测成功才能恢复。相关链路、地址或路由变化后，`notify_network_change` 会清除旧冷却、预置死亡状态并触发探测，使一次新的成功即可验证恢复。新注册节点有 60 秒宽限期；其间非强制失败会写入记录，但不计入死亡。探测历史为每个节点、域和地址族保留 100 条。

| 探测路径 | 行为 |
| --- | --- |
| TCP | 通过节点向 `tcp_check_url` 发送已配置 HTTP 方法；不适用 HTTP 探测时执行裸 TCP 连接。成功只把 RTT 记录到匹配的 TCP 地址族状态。 |
| UDP | 通过节点自己的 `dial_udp_transport`，向第一个 `udp_check_dns` 目标发送一个最小 DNS 查询。成功记录实测 RTT，并把 `DnsUdp` 与 `DataUdp` 都标记为存活；失败分别给两个 UDP 域增加一次探测失败。它从不修改 TCP 状态。 |
| 按组 URL | 探测动态解析出的 `(member tag, current leaf)` 对。状态为 TCP-only，一次失败即死亡，并使用相同冷却与连续两次成功恢复。重载时 `sync_group_check_urls` 替换有效的组/URL 注册表。 |

`has_udp_state` 区分从未观察过 UDP 的节点与已明确观察为死亡的节点。已建立 endpoint 的发送、接收和回包空闲错误会上报 `DataUdp` 流量失败。主动 endpoint 退役、节点死亡取消和进程关闭不影响健康状态。

alive→dead 转换会调用控制面死亡回调，清除该节点的池连接与 UDP endpoint，避免新流量取得陈旧的可复用对象。

每个节点最近一次真实 TCP 延迟样本每 60 秒写入 `cache.db`；启动时只恢复不超过 24 小时的样本。存活性从不由缓存恢复。合成 10 秒罚样本参与选择，但带有标记，不显示在历史中，也不会作为最近真实样本持久化。

## UDP 候选资格

UDP 选择按节点和地址族决定：

- `DataUdp` 存活或 `DnsUdp` 存活：可选择。
- 两个 UDP 域都明确死亡：排除，即使 TCP 存活。
- 从未记录过 UDP 状态：继承 TCP 存活性。

这样既不会让 TCP 健康但 UDP 已坏的节点继续吸引报文流，也不会惩罚尚未启用 UDP 探测的部署。

## eBPF 连通性发布

eBPF alive slot 属于组，而不是某个节点。对于每个域和地址族，发布值是所有可达叶成员状态的 OR。由单个节点转换触发的回调会重新计算该 OR；绝不会直接写入正在转换节点自身的值。

重载先把旧组或新组布局所需的所有 slot 设置为存活，使转换期 fail-open。发布新路由 generation 后，honk 再写入精确的新组快照。因此组重排不会继承陈旧的 ordinal 状态；若精确发布中途失败，尚未填写的转换 slot 保持 fail-open，而不会错误地杀死某个组。

## 预热与所有权

预热有三个相互独立的机制：

| 机制 | 候选与生命周期 | 保留资源 | 边界 |
| --- | --- | --- | --- |
| 启动预连接 | 仅在启动时运行一轮；先取各组当前选择，再按配置顺序。只有可池化裸 TCP 的代理节点合格。 | 向池中存入一条服务端裸 TCP 连接 | `'auto'` 最多选择 8 个节点；`0` 关闭。它不持有策略 retention bit。 |
| Selector 固定 | 始终跟踪每个 Selector 的配置叶节点，包括不健康的显式选择；多个组共享的叶节点按 UUID 去重。 | 一条 AnyTLS、VLESS H2MUX 或 VLESS Mux.Cool pool session；一个 QUIC client/connection；否则一条服务端裸 TCP | 有效选择变化会立即唤醒；10 秒周期修复丢失、已消费或已过期状态。 |
| UDP 预热集 | 需显式启用；每轮对每个地址族重新选择各组 top `min(N, 3)` 的可复用 UDP 叶节点，再按 UUID 全局去重。 | 协议的可复用 UDP-capable generation session 或 QUIC client | 最多并发 4 个预热尝试；进程保留集会重新排名并封顶 `4 × N`。 |

Selector 与 UDP 所有权是可复用节点 runtime 上相互独立的 bit。移除一个所有者时，如果另一个仍在，资源继续保留；只有最后一个所有者释放后，才会排空未来可复用状态。活跃流持有自己的 stream 或 connection 句柄，不会被切断。启动预连接只是 pool seed，不参与这些 bit。

重载时，配置未变化的节点会把现有 `NodeRuntime` 转移给替代 generation，其中包括存活的 AnyTLS、VLESS H2MUX/Mux.Cool 与 QUIC 状态。旧 generation 不再接受新的预热工作，活跃流则正常排空。健康探测会测量冷节点，但不会预热订阅中的每个成员。

## 拨号准入预算

`max_concurrent_dials` 默认为 64，并为物理代理连接和协议握手创建 generation-local semaphore。配置值会被启动时计算出的不可变进程级描述符 gate 限制。重载可以改变替代 generation 的本地上限，但重叠的新旧 generation 仍共享同一个进程 gate。

Ready 池命中、已热 generation transport 上打开的逻辑流，以及内置 `direct`/`block` 拨号不占额度。裸 TCP 池命中仍需执行协议握手，因此仍受拨号预算准入。

## 相关文档

- [出站设计](./outbound.md)
- [控制面设计](./control-plane.md)
- [组参考](../reference/groups.md)
- [全局参考](../reference/global.md)
