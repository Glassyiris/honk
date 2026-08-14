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
| `honk` | `honk` | With the default-off `honk-policy` Cargo feature, automatically selects one alive member from per-target, reliability-first scores; TCP and UDP and the target's IPv4/IPv6 family are independent. |

Policy matching is ASCII case-insensitive. The parser removes an optional parenthesized suffix before matching, which accepts `fixed(0)`. An unrecognized policy silently becomes `selector`, except that `honk` produces an actionable error when the binary was built without the required `honk-policy` feature.

If a group has exactly one unique leaf, no `final`, and that leaf is excluded by TCP health, honk still dials the same leaf as a last resort. The node remains marked dead until real traffic or probes recover it; this never implies a `direct` fallback. UDP keeps normal dead-member exclusion.

Every configured Selector proxy leaf stays warm. After resolving a nested choice, honk retains a reusable multiplexed session, a QUIC client, or one bare server TCP connection according to the leaf protocol; `direct` and `block` need no warm resource.

### Honk policy (optional)

`policy: honk` is accepted only when the default-off `honk-policy` Cargo feature is enabled. The feature is forwarded by `honk-core` and `honk-tool` to the configuration and outbound crates; it adds no runtime configuration knobs and changes no default policy. A build without the feature rejects `honk` explicitly and does not allocate scorer state.

Honk makes an authoritative single-member selection after the ordinary health filter has removed dead candidates. Health uses the proxy server's reachable IPv4/IPv6 family, independently of the business target family used for scoring; an IPv4 proxy server can therefore carry an IPv6 target. Among the remaining members, Honk ranks useful-outcome reliability first, then setup/first-response latency and a bounded throughput contribution. A bounded exploration bonus applies only while reliability is close. Cold-start exploration is deterministic, and final ties use declaration order and then stable node identity, so selection neither races members nor revives a dead one.

Scores are isolated by group, TCP or UDP, target IPv4 or IPv6 family, normalized exact target (lowercase domain or IP plus port), and node identity. Target-specific evidence is blended with bounded group/network/family aggregate evidence until enough exact samples exist. Work with a real target updates both levels; targetless warm-up updates aggregates only. Nested selection attributes one completed attempt to every Honk group traversed.

Feedback covers every actual attempt that traverses a Honk group: transparent TCP and UDP, DNS upstream exchanges, periodic HTTP/UDP health probes, on-demand Clash delay tests, startup/Selector/UDP warm-up, and external UI downloads. Target-bearing work uses its real host/IP, port, transport, and target family; server-only preconnect and session warm-up update aggregates without inventing a business target. Each periodic UDP cycle also runs a real TLS-in-QUIC handshake with ALPN `h3` through every node that belongs to a Honk group, targeting the first HTTPS `global.tcp_check_url`; that independent `DataUdp` sample affects Honk scoring but not the DNS-based UDP health verdict. An absent or non-HTTPS check URL disables this extra probe. The handshake records bidirectional usefulness without inventing wire-byte volume. Each started attempt records setup, first response when present, both byte directions, and one compact terminal outcome; cancelled or shutdown work is neutral, and retries are separate attempts.

All score state is process memory. It has a hard LRU limit of 4,096 exact node-target cells plus 4,096 bounded aggregate cells. Reload keeps the shared state and removes cells for deleted groups or members; a process restart clears it. Score cells and scorer-only domain/IP keys are not emitted to logs or Clash API documents or written to `cache.db`; established connection metadata is unaffected.

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
