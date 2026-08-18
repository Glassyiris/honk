# Experimental 配置参考

本文档说明 `experimental { ... }` 下支持的三个嵌套 section。

## Section 概览

| 嵌套 section | 用途 |
| --- | --- |
| `clash_api` | Clash 兼容 HTTP API 与外部 dashboard |
| `cache_file` | 用 SQLite 持久化运行时选择、模式、延迟样本和可选 DNS 状态 |
| `udp_nfqueue` | 对仍有歧义的 LAN 转发 UDP 使用保留首包决策路径 |

在嵌套 section 这一层，dae 解析器只将 `clash_api`、`cache_file` 和 `udp_nfqueue` 列入白名单；`experimental` 下不接受其他 section 名称。

## `clash_api`

| 字段 | 默认值 | 含义 |
| --- | --- | --- |
| `external_controller` | `""` | HTTP 监听地址。空值关闭 API server。 |
| `external_ui` | `""` | 外部 dashboard 目录。空值关闭 dashboard 服务与下载。 |
| `secret` | `""` | API 鉴权 secret。空值关闭鉴权。 |
| `default_mode` | `"Rule"` | 启动模式：`Rule`、`Global` 或 `Direct`。有效的缓存模式优先。 |

所有 `clash_api` 字段都由启动阶段持有。通过 SIGHUP 提交的候选配置只要修改其中任一字段就会被拒绝。

### 鉴权与传输

`secret` 非空时，API 请求使用 `Authorization: Bearer <secret>`；WebSocket upgrade 也可以改用 `?token=<secret>`。静态 `/ui` 内容不经过这层鉴权 middleware。内置 listener 只提供明文 HTTP，不提供 TLS。应绑定到 `127.0.0.1` 等 loopback 地址，或在前面部署带鉴权的 TLS reverse proxy；不得直接暴露到不受信任的网络。endpoint 清单见 [Clash API 参考](./api.md)。

### 外部 UI

绝对 `external_ui` 路径按原值使用。相对路径首先选择 `global.data_dir` 下的已有目录，其次选择相对当前工作目录的已有目录；两者都不存在时，honk 在 `global.data_dir` 下创建目标目录。目标缺失或为空时，会在后台下载 dashboard zip。`HONK_UI_DOWNLOAD_URL` 可覆盖 zip URL。

下载遵循普通流量的路由决策，并解析选中的组或节点。`block` 决策会中止下载，不会绕过策略。

### 启动模式

`default_mode` 接受规范模式 `Rule`、`Global` 和 `Direct`。`cache_file` 已启用且包含有效的 Clash 缓存模式时，改为恢复该值。无效的缓存值或配置值回退到 `Rule`。

## `cache_file`

| 字段 | 默认值 | 含义 |
| --- | --- | --- |
| `enabled` | `false` | 打开 SQLite 缓存并启用运行时状态持久化。 |
| `path` | `"cache.db"` | 数据库路径。绝对路径按原值使用。对相对路径，优先使用 `global.data_dir` 下的已有文件，其次使用相对原配置目录的已有旧路径；新文件创建在 `global.data_dir` 下。 |
| `cache_id` | `""` | 所有数据库 key 的 namespace。非空值给 key 加上 `<cache_id>:` 前缀。 |
| `store_fakeip` | `false` | 仅表示 FakeIP 持久化意图。已有 `fakeip:` 前缀和 flush API，但引擎尚不写入或恢复映射。 |
| `store_dns` | `false` | 使用 exact-key v2 格式持久化并恢复 DNS 缓存应答。 |

整个 `cache_file` section 都由启动阶段持有。通过 SIGHUP 提交的候选配置只要修改任一字段就会被拒绝。

### 始终持久化的状态

只要 `enabled` 成功打开数据库，honk 就会持久化 Selector 选择、Clash 模式和每个节点最后一次真实延迟样本，不受 `store_fakeip` 与 `store_dns` 影响。延迟样本每分钟生成一次快照；恢复时丢弃格式错误、为零或超过 24 小时的样本。liveness 不会恢复。

### DNS 持久化

`store_dns: true` 时，条目使用 `dns:v2:` key namespace 和 `HDNS` version-2 二进制 payload。v2 namespace 可安全回滚：pre-v2 binary 读取旧 `dns:` namespace 时会排除 `dns:v2:` 行，因此不会改动 v2 数据。

只有未过期，并且 key digest、规范 query wire、response wire identity 与当前 DNS policy 全部匹配的 v2 行才会恢复。exact key 还保留 ingress profile、request scope 和 operation，防止在不同 DNS 上下文之间复用。

## `udp_nfqueue`

| 字段 | 默认值 | 含义 |
| --- | --- | --- |
| `enabled` | `false` | 为仍有歧义的 LAN 转发 UDP 决策启用 NFQUEUE 暂存。 |

`enabled` 是唯一接受的设置。不存在 queue number、worker、bypass、fanout 或 fail-open 配置项。修改该值后必须重启进程；SIGHUP 会拒绝候选配置。以 `enabled: true` 启动时，构建必须带 `ebpf` feature 并使用真实 eBPF 后端。不带 `ebpf` 的构建或使用 `--mock-ebpf` 的运行会被拒绝。

### 流量范围

该路径只暂存仍有歧义的 LAN 转发 UDP 首包，位置在 LAN TC 之后、conntrack/NAT 之前。本机发起的 WAN 出站仍走 TPROXY 路径；DNS 53 端口、内部或特殊流量、反向流量、`must` 与 `block` 结果，以及已经可以安全直连的决策都不入队。机制和终态转换见 [NFQUEUE 设计](../design/nfqueue.md)。

### 所有权与生命周期

honk 独占 NFQUEUE 队列 `320` 和 nftables 对象 `inet honk_nfqueue` / `udp_decision`。honk 运行时，同一网络命名空间中的防火墙管理器不得创建、替换、flush 或删除这些对象。普通重启和清理会保留固定的 `UDP_DECISION_SEQUENCE` 分配器，避免复用 decision token。

### 损坏 pin 的恢复

分配器 pin 位于 `<bpf-pin-root>/UDP_DECISION_SEQUENCE`，通常是 `/sys/fs/bpf/UDP_DECISION_SEQUENCE`。只要仍有进程可能暂存报文，或仍可能存在存活的 token 绑定状态，就绝不能删除它。恢复损坏或不兼容的 pin 时：

1. 保持 NFQUEUE staging fenced；不得接纳新的暂存流。
2. 停止使用该网络命名空间和 pin root 的所有 honk 进程。
3. 确认队列 `320` 已无 listener，且 token 绑定 map `CONN_STATE_MAP`、`ROUTING_HANDOFF_MAP`、`REDIRECT_TRACK` 和 `UDP_DECISION_RETIRE_FENCE` 均已消失。只要仍有任一 map，就不得删除分配器 pin。
4. 仅删除 `UDP_DECISION_SEQUENCE`，且只删除一次。
5. 重启 honk，由它创建新的分配器。

## 示例

```dae
experimental {
    clash_api {
        external_controller: '127.0.0.1:9090'
        external_ui: 'zashboard'
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
    udp_nfqueue {
        enabled: true
    }
}
```

## 相关文档

- [Clash API 参考](./api.md)
- [NFQUEUE 设计](../design/nfqueue.md)
- [全局配置参考](./global.md)
