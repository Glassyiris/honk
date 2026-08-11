# 组参考

本文定义当前 `group { ... }` 配置面与成员选择语义。

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
| `final` | `final_outbound` | `null` | 没有存活成员时使用的节点、组、`direct` 或 `block`。 |
| `check_url` | `check_url` | `null` | 非 Selector 策略的按组 TCP 健康检查目标。Selector 会忽略该字段并告警。 |
| —（dae 中不可配置） | `check_interval` | `null` | 按组间隔字段，单位为秒。当前运行时不读取该字段，而使用全局间隔。 |
| —（dae 中不可配置） | `tolerance` | `50` | URLTest 切换阈值，单位为毫秒。dae URLTest 组接收 `global.check_tolerance`；运行时的有效下限为 1 ms。 |
| —（dae 中不可配置） | `idle_timeout` | `null` | URLTest 在不活跃后暂停探测的阈值，单位为秒。值为 `null` 时，健康检查层使用 1800 秒。 |
| —（dae 中不可配置） | `interrupt_connections` | `false` | Selector、URLTest 或 Fallback 的选择实际变化时关闭已跟踪连接。LoadBalance 轮转不会触发。 |
| —（dae 中不可配置） | `id` | 随机 UUID | 字段缺失时生成的内部组标识。 |

## 策略

| 规范名 | 接受的 dae 拼写 | 行为 |
| ------ | --------------- | ---- |
| `selector` | `selector`、`select`、`fixed`、`fixed(0)` | 依次使用运行时选择、`default` 和第一个存活成员；选择可以是直接节点或嵌套组 tag。 |
| `urltest` | `urltest`、`min_moving_avg`、`min_avg10`、`min_last_delay` | 使用减半移动平均 `(prev + sample) / 2` 和 tolerance 选择延迟最低的存活成员；TCP 与 UDP 选择相互独立。 |
| `loadbalance` | `loadbalance`、`roundrobin`、`round_robin`、`balance` | 对存活成员轮询；每个组以及 TCP/UDP 网络各有独立计数器。 |
| `fallback` | `fallback` | 分别为 TCP 和 UDP 按声明顺序固定第一个存活成员；更靠前的成员恢复后不会立即 failback。 |

策略名按 ASCII 大小写不敏感匹配。解析器匹配前会去掉可选的括号后缀，因此接受 `fixed(0)`；无法识别的策略会静默变为 `selector`。

若组只有一个唯一叶节点、未配置 `final`，且 TCP 健康状态排除了该节点，honk 仍会把同一节点作为最后尝试。节点保持 dead，直到真实流量或探测使其恢复；这绝不表示回退到 `direct`。UDP 继续正常排除死亡成员。

每个已配置 Selector 的代理叶节点都保持热态。解析嵌套选择后，honk 会按叶节点协议保留可复用的多路复用 session、QUIC client 或一条到服务端的裸 TCP 连接；`direct` 与 `block` 不需要热资源。

## 过滤解析

1. `group('tag')` 把嵌套 tag 加入 `groups`，不作为节点谓词求值。嵌套 tag 可以贡献该组当前策略选出的叶节点。
2. `name(...)` 匹配 `Node.name`。`subtag(...)` 把 `Node.subscription_id` 映射到当前订阅 tag 并匹配该 tag。普通参数是精确匹配，`keyword:` 是子串匹配，`regex:` 是原始正则表达式。匹配区分大小写；同一谓词中的多个参数互为候选。
3. 同一行中由 `&&` 连接的谓词按 AND 求值。在谓词前加 `!` 会对其取反。不同 `name(...)` 和 `subtag(...)` `filter:` 行之间按 OR 求值；`group(...)` 行加入嵌套候选。
4. 每次订阅刷新后都会重建过滤所得的成员关系。因此，稳定的节点 UUID 不会在订阅来源变化后保留过期成员关系。
5. 既没有节点过滤器也没有嵌套组的组会接收当前全部节点。只有嵌套组而没有节点过滤器的组只接收嵌套候选，不会接收全部节点。

## 嵌套组

嵌套选择深度上限为 8。组管理器构图时会删除每条闭环边并记录告警；未知的嵌套 tag 不会贡献候选。每个嵌套组贡献其自身策略选出的单个叶节点，因此每次拨号最终都会解析到一个节点。

面向 Clash 的组输出保留成员 tag：`all` 字段列出直接节点名和嵌套组 tag，而不展开嵌套组。面向叶节点的健康状态与连通性遍历会展开这些 tag 下的实际节点。

## 相关文档

- [节点参考](./nodes.md)
- [路由参考](./routing.md)
- [组设计](../design/groups.md)
