# Group Selection, Health, and Warm-up Design

This document explains how honk resolves groups to leaf outbounds, tracks their health, and retains bounded warm resources.

## Scope

The scope is `GroupManager`, `AliveDialerSet`, cold URLTest preparation, and the warm-resource coordinators. Group fields and policy syntax belong in the [group reference](../reference/groups.md); process-wide health, warm-up, and dial keys belong in the [global reference](../reference/global.md).

## Group manager and selection pipeline

`SharedGroupManager` is a stable, hot-swappable handle:

`Arc<parking_lot::RwLock<Arc<GroupManager>>>`

A reload builds a complete replacement `GroupManager`, migrates Selector choices whose group and member tag still exist, installs callbacks, and swaps the inner `Arc`. Readers therefore see either the old or the new manager, never a partially rebuilt graph.

The facade and its internals are split by responsibility:

| Module | Responsibility |
| --- | --- |
| `mod.rs` | `GroupManager` types, shared handle, and selection-plan entry points |
| `resolver.rs` | Nested-group expansion, member/leaf introspection, cycle cutting, and Selector-choice migration |
| `filter.rs` | Network- and family-specific liveness filtering |
| `policy.rs` | Selector, URLTest, LoadBalance, and Fallback picks and latency ranking |
| `state.rs` | URLTest/Fallback caches, Selector choices, idle timestamps, and callbacks |

Selection follows one invariant: after resolution and liveness filtering, the dial path uses exactly the policy pick. Selector returns its effective manual choice, URLTest its current winner, LoadBalance its next member, and Fallback its pin. The only multi-candidate exception is an unmeasured top-level URLTest group; all warm URLTest and non-URLTest plans are authoritative single-leaf plans.

## Policy semantics

| Policy | Runtime behavior |
| --- | --- |
| Selector | The runtime choice has precedence, then `default`, then the first eligible member. The Clash API changes the runtime choice. `PersistCallback` stores effective writes in `cache.db`; `InterruptCallback` closes tracked group connections when `interrupt_connections` is enabled. A configured but unhealthy choice remains a warm owner even while traffic temporarily selects another eligible member. |
| URLTest | Chooses the lowest halving moving average, keeps independent TCP and UDP selections, applies tolerance hysteresis, and re-evaluates lazily on dial and selection queries. A real selection change may invoke `InterruptCallback`. |
| LoadBalance | Round-robins eligible members in declaration order. Every group owns independent `AtomicUsize` cursors for TCP and UDP. Rotation never invokes `InterruptCallback`. |
| Fallback | Pins the first eligible member in declaration order independently for TCP and UDP. The pin stays until that member dies; recovery of an earlier member does not cause failback. |

### URLTest ranking and hysteresis

Latency uses a halving moving average:

`next = (previous + sample) / 2`

The first sample initializes the average. This is dae `min_moving_avg` behavior: recent changes matter quickly without making one jitter sample authoritative.

`SelectionNetwork::Tcp` and `SelectionNetwork::Udp` retain separate winners. TCP uses the TCP probe average, or the `(member tag, check_url)` average when the group has a custom target. UDP first uses `DataUdp`, then `DnsUdp`; if no eligible candidate has UDP measurements, it mirrors the TCP selection instead of inventing a UDP ranking from missing data. This gives the effective fallback order `DataUdp → DnsUdp → TCP`.

The effective tolerance is `max(configured tolerance, 1 ms)`. The incumbent stays selected while:

`best latency + tolerance >= incumbent current measured latency`

The incumbent baseline is read again at selection time, not retained from the moment it won. A degraded incumbent can therefore be replaced; this matches sing-box `Select()` behavior.

A dial failure clears that node's latency history and inserts one synthetic 10-second penalty sample. The next dial re-evaluates immediately, while one later fast sample cannot return a flaky node directly to first place.

A group `check_url` creates independent TCP-only liveness and latency state keyed by `(member tag, check_url)`. A failure removes that member only from groups using that target. Selector groups ignore `check_url` and emit a warning. URLTest probing sleeps after `idle_timeout`; an unset timeout uses the 30-minute health-layer default, and the next real selection wakes probes immediately.

## Nested groups and member identity

`Group.groups` names sub-groups. Each sub-group contributes exactly one candidate: the leaf selected by that sub-group's own policy for the current network and address family. The parent ranks or pins that candidate as one member rather than merging every descendant into its policy.

Resolution is bounded by `MAX_GROUP_DEPTH = 8` and a per-walk visited set. Construction also runs DFS over group edges and cuts every cycle-closing edge with a warning. These checks prevent a malformed graph from hanging selection or introspection.

Identity remains the member tag even when the physical dial reaches a deeper leaf:

| API | Identity returned |
| --- | --- |
| `node_names_in_group` | Direct node tags plus sub-group tags |
| `leaf_node_names_in_group` | Deduplicated real leaf nodes reachable below the group |
| `delay_test_members` | One `(member tag, current leaf)` pair per effective member |
| `selection_chain` | Current chain from group through selected sub-groups to the leaf |

Custom-URL probes resolve `delay_test_members` again on every cycle. A sub-group is probed through its current pick, but the result is recorded under the sub-group tag. The parent therefore treats the sub-group as one stable member, matching sing-box RealTag semantics.

## Cold URLTest UDP preparation

Only a top-level URLTest plan with no usable measurement may prepare several UDP transports. Candidate starts use absolute offsets `0 ms`, `30 ms`, `80 ms`, then one every `80 ms`; at most three preparations are in flight. Absolute scheduling prevents an earlier slow attempt from shifting all later starts.

The first successful candidate that is still eligible wins. honk aborts and drains every started loser before binding the winner to an endpoint, rechecks eligibility, then commits protocol state before endpoint publication or the first application send.

Only an observed preparation `Err` affects traffic health. Never-started work, cancellation, an ineligible successful result, and successfully drained losers are neutral; a completed error discovered while draining is still an observed error and counts. AnyTLS uses caller-owned provisional pool slots so losers never publish sessions. QUIC protocols build detached clients and publish only the finalized winner; losing clients are closed with their speculative work.

## Health state and probes

`AliveDialerSet` keys node health, registrations, histories, emergency triggers, and latency collections by the node's `NodeId` UUID. Display names are metadata for logs and probe lookup, not identity. Every node has six independent states: three domains across IPv4 and IPv6.

| Failure source | `Tcp` | `DnsUdp` | `DataUdp` |
| --- | ---: | ---: | ---: |
| Periodic probe | 1 | 3 | 3 |
| Real traffic | 10 | 3 | 50 |

Probe and traffic failures have separate counters. Probe failures apply exponential cooldown from 5 seconds to 300 seconds. A separate `min(5s, check_interval)` recovery scheduler considers only dead domain/family states whose cooldown is due; deep-backoff states continue at the 300-second cadence rather than stopping permanently.

A dead state normally needs two consecutive probe successes to recover. `notify_network_change` clears stale cooldowns after a relevant link, address, or route change, primes dead states, and triggers probes so one fresh success can verify recovery. Newly registered nodes receive a 60-second grace period during which non-forced failures are recorded but do not count toward death. Probe history retains 100 entries per node, domain, and address family.

| Probe path | Behavior |
| --- | --- |
| TCP | Sends the configured HTTP method to `tcp_check_url` through the node, or performs a raw TCP connect when no HTTP probe applies. Success records RTT only in the matching TCP family state. |
| UDP | Sends one minimal DNS query to the first `udp_check_dns` target through the node's own `dial_udp_transport`. Success records the measured RTT and marks both `DnsUdp` and `DataUdp` alive; failure adds one probe failure to each UDP domain. It never changes TCP state. |
| Per-group URL | Probes the dynamically resolved `(member tag, current leaf)` pairs. State is TCP-only, dies after one failure, and uses the same cooldown and two-success recovery. `sync_group_check_urls` replaces the active group/URL registry on reload. |

`has_udp_state` distinguishes a node with no UDP observations from one explicitly observed dead. Established endpoint send, receive, and reply-idle errors report `DataUdp` traffic failures. Intentional endpoint retirement, node-death cancellation, and process shutdown are health-neutral.

An alive-to-dead transition invokes the control-plane death callback, which purges the node's pooled connections and UDP endpoints so no stale reusable object is handed to new traffic.

The last real TCP delay sample per node is written to `cache.db` every 60 seconds and restored at startup only when it is at most 24 hours old. Liveness is never restored from the cache. Synthetic 10-second penalties participate in selection but are flagged, excluded from display history, and never persisted as the last real sample.

## UDP candidate eligibility

UDP selection is decided per node and address family:

- `DataUdp` alive or `DnsUdp` alive: selectable.
- Both UDP domains explicitly dead: excluded, even if TCP is alive.
- No UDP state has ever been recorded: inherit TCP liveness.

This keeps a TCP-healthy but UDP-broken node from attracting packet flows without penalizing deployments that have not enabled UDP probing yet.

## eBPF connectivity publication

The eBPF alive slot belongs to a group, not to one node. For every domain and address family, the published value is the OR of all reachable leaf-member states. A callback caused by one node transition recomputes that OR; it never writes the transitioning node's value directly.

Reload first sets every slot needed by the old or new group layout to alive, making the transition fail-open. After the new routing generation is published, honk writes the exact new group snapshot. Reordered groups therefore cannot inherit stale ordinal state; if exact publication fails partway, unfilled transition slots remain fail-open rather than falsely killing a group.

## Warm-up and ownership

Warm-up has three independent mechanisms:

| Mechanism | Candidate and lifetime | Retained resource | Bounds |
| --- | --- | --- | --- |
| Startup preconnect | One startup-only pass; current group picks first, then config order. Only bare-TCP-poolable proxy nodes qualify. | One bare server TCP connection deposited in the pool | `'auto'` selects at most 8 nodes; `0` disables it. It owns no policy-retention bit. |
| Selector pin | Always tracks every Selector's configured leaf, including an unhealthy explicit choice; shared leaves are UUID-deduplicated. | One AnyTLS, VLESS H2MUX, or VLESS Mux.Cool pool session; one QUIC client/connection; otherwise one bare server TCP | Effective-choice changes wake immediately; a 10-second pass repairs lost, consumed, or expired state. |
| UDP warm set | Opt-in; re-ranks each group's top `min(N, 3)` reusable UDP leaves for each address family on every pass, then UUID-deduplicates globally. | The protocol's reusable UDP-capable generation session or QUIC client | At most 4 warm attempts run concurrently; the retained process set is re-ranked and capped at `4 × N`. |

Selector and UDP ownership are independent bits on reusable node runtimes. Removing one owner leaves the resource retained for the other; only the final owner release drains future reusable state. Active flows keep their own stream or connection handles and are not cut. Startup preconnect is only a pool seed and does not participate in these bits.

On reload, unchanged node configurations transfer their existing `NodeRuntime`, including live AnyTLS, VLESS H2MUX/Mux.Cool, and QUIC state, to the replacement generation. The old generation becomes terminal to new warm work while active flows drain normally. Health probes measure cold nodes but do not warm every subscription member.

## Dial admission budget

`max_concurrent_dials` defaults to 64 and creates a generation-local semaphore for physical proxied connects and protocol handshakes. The configured value is clamped to the immutable process-wide descriptor gate computed at startup. Reload may change the replacement generation's local limit, but overlapping old and new generations still share that same process gate.

Ready-pool hits, logical streams opened on an already warm generation transport, and built-in `direct`/`block` dials are exempt. A bare-TCP pool hit still runs its protocol handshake and therefore remains admitted by the dial budget.

## Related docs

- [Outbound design](./outbound.md)
- [Control-plane design](./control-plane.md)
- [Group reference](../reference/groups.md)
- [Global reference](../reference/global.md)
