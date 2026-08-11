# Group reference

This page defines the current `group { ... }` configuration surface and member-selection semantics.

## Syntax

Each group is a named subsection of `group { ... }`:

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

## Keys

| dae key | Internal field | Default | Meaning |
| ------- | -------------- | ------- | ------- |
| (section name) | `name` | required | Group tag used as an outbound in routing and APIs. |
| `policy` | `policy` | `selector` | Member-selection policy; accepted spellings are listed below. |
| `filter: name(...)` | `filters` + `nodes` | `[]` | Select nodes by node name. The parser resolves matches to node UUIDs. |
| `filter: subtag(...)` | `filters` + `nodes` | `[]` | Select nodes by the current tag of the subscription that produced them. |
| `filter: group(...)` | `groups` | `[]` | Add nested group tags. Comma-separated arguments and pipe-separated tags are accepted. |
| `default` | `default` | `null` | Initial or fallback member tag for `selector`. |
| `final` | `final_outbound` | `null` | Node, group, `direct`, or `block` used when no member is alive. |
| `check_url` | `check_url` | `null` | Per-group TCP health-check target for non-Selector policies. A Selector ignores it with a warning. |
| — (not in dae) | `check_interval` | `null` | Per-group interval field in seconds. The current runtime does not consult it and uses the global interval. |
| — (not in dae) | `tolerance` | `50` | URLTest switch threshold in milliseconds. dae URLTest groups receive `global.check_tolerance`; the runtime applies an effective minimum of 1 ms. |
| — (not in dae) | `idle_timeout` | `null` | URLTest probe-suspension threshold after inactivity, in seconds. With `null`, the health layer uses 1800 seconds. |
| — (not in dae) | `interrupt_connections` | `false` | Close tracked connections on an actual Selector, URLTest, or Fallback selection change. LoadBalance rotation does not trigger it. |
| — (not in dae) | `id` | random UUID | Internal group identity generated when the field is absent. |

## Policies

| Canonical name | Accepted dae spellings | Behavior |
| -------------- | ---------------------- | -------- |
| `selector` | `selector`, `select`, `fixed`, `fixed(0)` | Uses the runtime choice, then `default`, then the first alive member; the choice may be a direct node or nested group tag. |
| `urltest` | `urltest`, `min_moving_avg`, `min_avg10`, `min_last_delay` | Selects the lowest-latency alive member using the halving moving average `(prev + sample) / 2` and tolerance; TCP and UDP selections are independent. |
| `loadbalance` | `loadbalance`, `roundrobin`, `round_robin`, `balance` | Round-robins over alive members with independent counters per group and TCP/UDP network. |
| `fallback` | `fallback` | Pins the first alive member in declaration order independently for TCP and UDP; recovery of an earlier member does not immediately fail back. |

Policy matching is ASCII case-insensitive. The parser removes an optional parenthesized suffix before matching, which accepts `fixed(0)`; an unrecognized policy silently becomes `selector`.

Every configured Selector proxy leaf stays warm. After resolving a nested choice, honk retains a reusable multiplexed session, a QUIC client, or one bare server TCP connection according to the leaf protocol; `direct` and `block` need no warm resource.

## Filter resolution

1. `group('tag')` adds nested tags to `groups`; it is not evaluated as a node predicate. A nested tag may contribute the leaf selected by that group's current policy.
2. `name(...)` matches `Node.name`. `subtag(...)` maps `Node.subscription_id` to the current subscription tag and matches that tag. Plain arguments are exact matches, `keyword:` is a substring match, and `regex:` is a raw regular expression. Matching is case-sensitive; multiple arguments in one predicate are alternatives.
3. Predicates joined by `&&` on one line are AND-ed. Prefixing a predicate with `!` negates it. Separate `name(...)` and `subtag(...)` `filter:` lines are OR-ed; `group(...)` lines add nested candidates.
4. Filter-derived membership is rebuilt after every subscription refresh. Stable node UUIDs therefore do not retain stale membership after their subscription provenance changes.
5. A group with neither node filters nor nested groups receives all current nodes. A group with nested groups but no node filters receives only its nested candidates, not all nodes.

## Nested groups

Nested selection is depth-capped at 8. When the group manager builds the graph, it removes each cycle-closing edge and logs a warning; an unknown nested tag contributes no candidate. Each nested group contributes the single leaf selected by its own policy, so every dial ultimately resolves to one node.

Clash-facing group output preserves member tags: the `all` field lists direct node names and nested group tags rather than expanding nested groups. Leaf-facing health and connectivity traversal expands the real nodes below those tags.

## Related docs

- [Node reference](./nodes.md)
- [Routing reference](./routing.md)
- [Group design](../design/groups.md)
