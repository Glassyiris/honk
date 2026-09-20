# 组参考

本页定义当前 `group { ... }` 配置面与成员选择语义。每份配置最多可定义 250 个顶层用户组；更高的路由序号由 ABI 保留。

## 语法

每个组都是 `group { ... }` 中的命名子节：

```dae
group {
    hk {
        filter: subtag('airport') && name(keyword: 'HK')
        filter: name(regex: '^Hong Kong ')
        policy: min_moving_avg
        check_url: 'https://www.gstatic.com/generate_204'
        final: direct
    }

    proxy {
        filter: group('hk')
        filter: name('backup')
        policy: select
        default: 'hk'
        final: direct
    }
}
```

## 键

| dae 键 | 内部字段 | 默认值 | 含义 |
| ------- | -------- | ------ | ---- |
| （子节名） | `name` | 必填 | 在路由和 API 中用作出站的组 tag。 |
| `policy` | `policy` | `selector` | 成员选择策略；接受的拼写见下表。 |
| `filter: name(...)` | `filters` + `nodes` | `[]` | 按节点名选择节点。解析器把匹配结果解析为节点 UUID。 |
| `filter: subtag(...)` | `filters` + `nodes` | `[]` | 按产生节点的订阅的当前 tag 选择节点。 |
| `filter: group(...)` | `groups` | `[]` | 加入嵌套组 tag。接受逗号分隔的参数和竖线分隔的 tag。 |
| `default` | `default` | `null` | `selector` 的初始或回退成员 tag。 |
| `final` | `final_outbound` | `null` | 组策略没有合格选择时使用的节点、组、`direct` 或 `block`，该组嵌套在其他组中时同样生效。Final 节点仍受健康检查约束；缺失或成环的 final 会拒绝，不会隐式直连。 |
| `check_url` | `check_url` | `null` | 非 Selector 策略的按组 TCP 健康检查目标。Selector 会忽略该字段并告警。 |
| —（dae 中不可配置） | `check_interval` | `null` | 按组间隔字段，单位为秒。当前运行时不读取该字段，而使用全局间隔。 |
| —（dae 中不可配置） | `tolerance` | `50` | URLTest 切换阈值，单位为毫秒。dae URLTest 组接收 `global.check_tolerance`；运行时的有效下限为 1 ms。 |
| —（dae 中不可配置） | `idle_timeout` | `null` | URLTest 在不活跃后暂停探测的阈值，单位为秒。值为 `null` 时，健康检查层使用 1800 秒。 |
| —（dae 中不可配置） | `interrupt_connections` | `false` | 请求在选择变化时移除连接跟踪记录，不会取消正在运行的转发任务。值为 true 时在 `groups[index].interrupt_connections` 产生 `ineffective-option`，结构化配置和通过代码构造的配置也不例外。 |
| —（dae 中不可配置） | `id` | 随机 UUID | 字段缺失时生成的内部组标识。 |

## 策略

| 规范名 | 接受的 dae 拼写 | 行为 |
| ------ | --------------- | ---- |
| `selector` | `selector`、`select`、`fixed`、`fixed(0)` | 在健康过滤前依次使用运行时选择、`default` 和第一个现存成员，TCP 与 UDP 语义一致。健康状态不会把有效选择替换成兄弟成员。选择可以是直接节点或嵌套组 tag。 |
| `urltest` | `urltest`、`min_moving_avg`、`min_avg10`、`min_last_delay` | 使用减半移动平均 `(prev + sample) / 2` 和 tolerance 选择延迟最低的存活成员；TCP 与 UDP 选择相互独立。 |
| `loadbalance` | `loadbalance`、`roundrobin`、`round_robin`、`balance` | 对存活成员轮询；每个组以及 TCP/UDP 网络各有独立计数器。 |
| `fallback` | `fallback` | 分别为 TCP 和 UDP 按声明顺序固定第一个存活成员；更靠前的成员恢复后不会立即 failback。 |
| `score` | `score` | 根据实际可靠性、新鲜目标质量与有界验证选择一个存活成员；TCP/UDP 和目标 IPv4/IPv6 证据各自隔离。 |

策略名按 ASCII 大小写不敏感匹配。解析器匹配前会去掉可选的括号后缀，因此接受 `fixed(0)`。无法识别的策略会变为 `selector`，并在诊断信息中注明组名；旧策略名 `honk` 明确无效，必须改用 `score`。

只有在选择缺失或已不属于该组时，才继续使用 `default` 或声明顺序中的第一个成员。现存的已选成员没有合格叶节点时，TCP 和 UDP 都不会回退到兄弟成员：仅可继续执行显式配置的 `final` 或下述同一叶节点的 TCP 最后尝试。选中的嵌套组仍执行自己的策略，因此 URLTest 可以在该子组内部选择其他叶节点。

已选子组会先解析自己的显式 `final`，再向父组返回空结果。这不允许改选其他 Selector 兄弟成员，也不允许重试终态协议拒绝。IPv6 目标仍优先尝试经 IPv4 代理健康状态可达的普通已选叶节点，然后才执行 final 路径。

UDP 资格同时要求协议／配置支持和健康条件；VMess 与显式仅支持 TCP 的叶节点在选择及 Score 比较前被排除，TCP 选择不受影响。Selector 已选节点不具备 UDP 能力并不允许改选兄弟成员，内置 `block` 仍保持终态。能力过滤不能绕过已选节点针对具体目标的 UDP 策略拒绝。

不同节点使用同一显示 tag 时，Selector 在健康过滤前按组内声明顺序绑定第一个匹配成员的 `NodeId`，不会因另一个同名节点健康而改选它。
按名称指定的 `final` 节点同样绑定配置中第一个匹配声明，不会用健康的同名节点替换；选择与 final 节点健康注册使用同一身份。

若组只有一个唯一叶节点、未配置 `final`，且 TCP 健康状态排除了该节点，honk 仍可把同一节点作为最后尝试，但当前 Selector 选择路径必须能到达它。这不能绕过选中的空子组，也不表示回退到 `direct`。节点保持 dead，直到真实流量或探测使其恢复；UDP 继续正常排除死亡成员。最后尝试服务会记录限流警告（每组 60 秒）。

每个已配置 Selector 的代理叶节点都保持热态。解析嵌套选择后，honk 会按叶节点协议保留可复用的多路复用 session、QUIC client 或一条到服务端的裸 TCP 连接；`direct` 与 `block` 不需要热资源。

### Score 策略

Score 始终编译，必须以 `policy: score` 显式选择；省略策略仍默认 Selector。没有运行时调节项。可靠性保护准入，但更多历史成功次数本身不能长期排除已经验证且更快的少样本节点。

Score 经普通健康过滤后选择一个权威叶节点；代理健康地址族与业务目标地址族独立。普通排名、性能基准与现任保护共用资格，充分观测的候选比较实际失败风险和近期性能，而不是样本最多者的下置信界。证据稀疏者获得有界试用。配置探测质量只是基线，新鲜可信的目标业务证据仍可覆盖它；平局按声明顺序与稳定身份解决。

冷启动预算为四个及以下覆盖全部，否则 `ceil(sqrt(n)) + 1`。后续机会在距前次试用 30 秒、累计 `clamp(2n,16,64)` 次选择，或出现退化且已过至少 16 次选择后产生，但只用于未解决的证据缺口。有希望且持续进展的候选最多获得八次集中试用；取消或无进展则公平轮转。触发条件共享组/网络/目标地址族预算，Peek 和新目标不能产生新预算，新鲜等价候选停止强制采样。试用不获得普通现任保护，真实失败保留指数退避和三连败普通排除，退避到期仍允许恢复试用。

业务可靠性仍使用 30 分钟半衰期；性能置信度独立老化，120 秒后过期，不受样本数量影响。setup 与首响应即时发布，已接受的传输进展使用互不重叠的 1–10 秒窗口，被测方向至少 64 KiB 且 flow 已有双向进展和响应。窗口不增加终态成功或失败次数。goodput 受业务需求影响，不等于链路容量，静默不是拥塞。现任保持在八次有效完成后达到 `0.005`，支撑量取适用层分别衰减后的最大值。不合格现任和未恢复的业务失败可绕过保持；已恢复的历史失败量不再单独取消保护。健康现任的替换需要双方合格的共同性能依据或有充分支撑的实际可靠性优势，不能只靠对手缺失数据获益。常量仍不可配置，详见[生命周期设计](../design/groups.md#score-评分与生命周期)。

已完成 setup 且已有 TX 的定向 Traffic RX，可在 flow 结束前恢复普通现任保护，但不清除连败、不增加终态成功。首次合格 RX 立即发布，后续按事件驱动且每个 reporter 每秒至多一次；被限频的接收需要等待下一次可发布 RX 或终态。四个有效 useful 完成与新鲜业务 RX 可取得 60 秒资格租约，租约内 RX 可续期而不扩大证据计数。失败／reload 使租约失效；低于完成数门槛的候选不能仅凭 RX 恢复已过期租约。普通选路的这些规则不会放宽 `scoreVerification` 的终态证据要求。

业务评分仍按组、transport、目标地址族、规范化目标和节点身份隔离；全局/地址族/精确目标可靠性分层混合，但不把重叠完成数相加。目标性能仅在新鲜可比时覆盖基线。探测 RTT 单独保留 protocol/family 与规范化 HTTP URI/方法身份；预热只提供 setup 质量。一次真实结果向经过的每个 Score 组归因一次。

透明 TCP/UDP、受支持的 DNS exchange 和 UI 下载反馈真实业务 attempt。配置 HTTP/UDP/QUIC 探测提供近期质量，不增加业务成功或清除真实连败。手动 Clash delay 保留 Alive/API 历史，但不建立配置 Score 基线，也不把任意目标失败变成真实拨号降级；实际准备仍记预热质量。独立 Score QUIC 握手保留既有 DataUdp 健康恢复，不虚构字节流量。

持续且实际测得的 carrier 压力可以重新打开预算内比较，但不增加业务失败，也不直接改变赢家。这是 honk→代理服务器的提示证据，不是端到端 UDP 丢包率或首请求保证；不支持观测的路径仍未知。详见[提示范围](../design/groups.md#score-评分与生命周期)。

全部评分状态仅存于当前进程内存。精确 node-target cell 使用硬上限为 4,096 的 LRU，聚合 cell 使用另一个 4,096 项 LRU。精确目标证据衡量的是实际 transport 质量，不表示服务在语义上已解锁；需要这种粗粒度 cohort 时，应使用已有 routing 或 geosite 规则选择专用的服务 Score 组。成功的进程内 reload 复用同一共享状态并移除已删除组或成员的 cell；进程重启会清空状态。评分 cell 与仅由 scorer 持有的 domain/IP 键不会进入日志、持久化存储或任何 API 输出。Clash 仍将 Score 表示为 `type: "url_test"`，在 `now` 中显示当前聚合 TCP 胜者，并拒绝对该组执行 `PUT /proxies/{name}`。

可重试的 TCP 建立失败后，Score 所属请求至多顺序尝试一个不同的合格叶节点，不要求普通评分先改选。两次尝试共享 deadline 和既有拨号准入；Selector 边界与首选实际经过的 final 边保持权威，不新增 direct/final 兜底或重放应用负载。提交 reload 时清空探测基线，但保留有效在途业务证据；中性 cell 仍受既有 LRU 容量约束。

每次已授权的多候选 rank 只记录一个互斥原因：`coldExplore`、`periodicExplore`、`incumbentIneligible`、`freshFailureBypass`、`insufficientEvidenceHeld`、`incumbentHeld`、`reliabilityWinner` 或 `performanceWinner`。`ordinarySwitch` 记录同作用域普通已提交 A→B 变更，不含首次选择和试用；`switchFlap` 是其中八次普通选择内返回前一赢家的子集。候选过滤／退避计数保持独立。Peek 与展示/API 读取保持中性。经鉴权的 `/stats.score.groups[]` 只导出固定组／网络计数，`/stats.score.cache` 描述两个有界证据 LRU。详见 [API 原因语义](./api.md#score-选路原因字段)，不导出 scorer 私有节点或目标身份。

采样在共享预算内解决明确的可用性/响应缺口，有进展的候选最多连续获得八次集中试用；新鲜等价候选停止强制采样，缺少传输证据则等待真实负载。新增 `scoreVerification` 区分临时转发、已观测可用性、限定比较、证据范围/有效期及下一步，详见 [API 验证](./api.md#score-验证信息)。这些是可撤销的经验结论，不是最优候选识别或未来网络行为的保证。

## 过滤解析

1. 单独的 `group('tag')` 行把嵌套 tag 加入 `groups`，不作为节点谓词求值。嵌套 tag 可以贡献该组当前策略选出的叶节点。包含其他谓词或尾随文本的 `group(...)` 行会被忽略并报告诊断信息；如果组内只有这一条过滤器，该组的成员为空。
2. `name(...)` 匹配 `Node.name`。`subtag(...)` 把 `Node.subscription_id` 映射到当前订阅 tag 并匹配该 tag。普通参数是精确匹配，`keyword:` 是子串匹配，`regex:` 是原始正则表达式。匹配区分大小写；同一谓词中的多个参数互为候选。
3. 同一行中由 `&&` 连接的谓词按 AND 求值。在谓词前加 `!` 会对其取反。不同 `name(...)` 和 `subtag(...)` `filter:` 行之间按 OR 求值；单独的 `group(...)` 行加入嵌套候选。
4. 每次订阅刷新后都会重建过滤所得的成员关系。因此，稳定的节点 UUID 不会在订阅来源变化后保留过期成员关系。
5. 既没有节点过滤器也没有嵌套组的组会接收当前全部节点。显式 `group()`、空过滤器、空嵌套组或订阅刷新后变空的过滤器均不选择节点。这些空贡献在 JSON/YAML/TOML 序列化往返和刷新后仍保留；有效的同级过滤器继续按 OR 贡献候选，`final` 保持独立。

honk 会忽略无法解析的过滤器，并在诊断中注明其在组内节点过滤器中的序号；只有非空的独立 `group(...)` 行不参与计数，混合谓词行仍参与计数。`group()` 产生 `empty-subgroup` 警告。需要全部节点时请删除过滤器；显式 `group()` 现在不选择任何节点。注入的 `direct` 与 `block` 是出站，不是节点池成员：无过滤器的组、`keyword:`、`regex:` 与 `subtag(...)` 都不会选中它们，只有按名字写出的过滤器（`filter: name(direct)`）才会收入。

## 嵌套组

嵌套选择深度上限为 8。组管理器构图时会删除每条构成环的边并记录警告；未知的嵌套 tag 不会贡献候选。每个嵌套组贡献其自身策略选出的单个叶节点，因此每次拨号最终都会解析到一个节点。

面向 Clash 的组输出保留成员 tag：`all` 字段列出直接节点名和嵌套组 tag，而不展开嵌套组。面向叶节点的健康状态与连通性遍历会展开这些 tag 下的实际节点。

## 相关文档

- [节点参考](./nodes.md)
- [路由参考](./routing.md)
- [组设计](../design/groups.md)
