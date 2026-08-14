# Group Selection, Health, and Warm-up Design

This document explains how honk resolves groups to leaf outbounds, tracks their health, and retains bounded warm resources.

## Scope

The scope is `GroupManager`, `AliveDialerSet`, the optional Honk scorer, cold URLTest preparation, and the warm-resource coordinators. Group fields and policy syntax belong in the [group reference](../reference/groups.md); process-wide health, warm-up, and dial keys belong in the [global reference](../reference/global.md).

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
| `honk.rs` | Feature-gated Honk scoring, exact-once feedback, and target-aware selection |
| `state.rs` | URLTest/Fallback caches, Selector choices, idle timestamps, and callbacks |

Selection follows one invariant: after resolution and liveness filtering, the dial path uses exactly the policy pick. Selector returns its effective manual choice, URLTest its current winner, LoadBalance its next member, and Fallback its pin. The only multi-candidate exception is an unmeasured top-level URLTest group; all warm URLTest and non-URLTest plans are authoritative single-leaf plans. If a group with no `final` has exactly one unique leaf and TCP liveness excludes it, that same leaf remains an authoritative last resort: its health stays dead, but a real dial can prove recovery without leaking to `direct`. UDP keeps normal liveness exclusion.

## Policy semantics

| Policy | Runtime behavior |
| --- | --- |
| Selector | The runtime choice has precedence, then `default`, then the first eligible member. The Clash API changes the runtime choice. `PersistCallback` stores effective writes in `cache.db`; `InterruptCallback` closes tracked group connections when `interrupt_connections` is enabled. A configured but unhealthy choice remains a warm owner even while traffic temporarily selects another eligible member. |
| URLTest | Chooses the lowest halving moving average, keeps independent TCP and UDP selections, applies tolerance hysteresis, and re-evaluates lazily on dial and selection queries. A real selection change may invoke `InterruptCallback`. |
| LoadBalance | Round-robins eligible members in declaration order. Every group owns independent `AtomicUsize` cursors for TCP and UDP. Rotation never invokes `InterruptCallback`. |
| Fallback | Pins the first eligible member in declaration order independently for TCP and UDP. The pin stays until that member dies; recovery of an earlier member does not cause failback. |
| Honk (optional) | With the default-off `honk-policy` Cargo feature, chooses one authoritative alive member using automatic target-aware, reliability-first scoring and bounded deterministic exploration. |

### Honk scoring and lifecycle

Honk first runs the same liveness filter as every other policy. The filter's health family describes connectivity to the proxy server; the separately carried target family selects the scoring bucket. Consequently a server reached over IPv4 remains eligible for an IPv6 business target, while no score can return a node already excluded as dead.

The exact key is `(group, TCP/UDP, target IPv4/IPv6, normalized target, NodeId)`. Domains are ASCII-lowercased with one trailing dot removed and retain their port; IP targets retain the socket address. A second bounded `(group, TCP/UDP, optional target family, NodeId)` aggregate supplies the prior for cold targets and receives targetless warm-up samples. The target-family aggregate and exact layer each phase in reliability and throughput over their first eight terminal useful outcomes, and setup latency separately over their first eight setup completions. The family layer falls back to the global aggregate, so setup-only preparation cannot erase known reliability. Recursive selection carries the same target context and attributes the leaf outcome to every Honk group on the path.

Each cell retains compact counters for starts, setup and useful outcomes; EWMA setup/first-response latency and bounded `log2(1 + bytes/second)` throughput; and last use. Setup failure is the strongest reliability penalty. Useful success requires a successful terminal outcome and nonzero traffic in both directions, so raw byte volume is not itself a reward. Error strings are reduced to compact outcome categories before feedback enters the state.

`HonkFeedback::start()` is called only when a physical dial, logical stream, transport preparation, or exchange actually starts. Its cloneable reporter records setup, first response, transmitted/received bytes, and exactly one of success, timeout, `io::ErrorKind`, cancellation, shutdown, or other; the first terminal call wins and dropping the last unfinished handle reports cancellation. Cancellation and shutdown remove the start rather than degrading reliability. A retry starts a new reporter, while speculative work that never starts has no reporter.

The same reporter path covers transparent TCP relay and UDP endpoint lifetime, supported DNS upstream exchanges, periodic HTTP/UDP health probes, on-demand Clash delay measurements, startup preconnect, Selector/session and UDP warm-up, and external UI downloads. DNS feedback follows the carrier actually attempted: UDP uses the UDP bucket, TCP/DoT/DoH use TCP, and a TCP retry after a truncated UDP answer switches buckets; the existing restriction on proxied DoQ/DoH3 remains unchanged. With `honk-policy`, every periodic UDP cycle separately opens a packet transport for each node in a Honk group and completes a real `h3` TLS-in-QUIC handshake to the first HTTPS `global.tcp_check_url`. That exact-target `DataUdp` score is independent of the DNS exchange that determines UDP liveness; missing or non-HTTPS URLs disable it. Because the adapter has no wire counters, a successful handshake records bidirectional usefulness but no byte-volume reward. URL tests and downloads use the real requested target for both proxy and built-in `direct` leaves. Periodic direct liveness still uses its stable bootstrap target, and server/session-only warm work updates only aggregate setup evidence.

Ranking begins with a Beta-prior lower confidence estimate of useful reliability. Candidates more than the fixed close-reliability band below the best are excluded from latency, throughput, and UCB exploration. Within that band, lower setup/first-response latency, bounded throughput, and bounded exploration contribute to utility. Completely cold candidates are visited deterministically; remaining ties use declaration order and stable `NodeId`. The resulting plan always contains one authoritative leaf rather than racing candidates.

The shared, mutex-protected state is memory-only: exact cells use a 4,096-entry LRU and aggregate cells use a separate bounded 4,096-entry LRU. A committed reload reuses the state, publishes the new valid `(group, member)` set, and prunes removed cells; late feedback for deleted membership is ignored. Process restart clears everything. No score cell or scorer-only target data is emitted to logs or Clash API documents or written to `cache.db`; the existing `/connections` destination metadata remains unchanged.

### URLTest ranking and hysteresis

Latency uses a halving moving average:

`next = (previous + sample) / 2`

The first sample initializes the average. This is dae `min_moving_avg` behavior: recent changes matter quickly without making one jitter sample authoritative.

`SelectionNetwork::Tcp` and `SelectionNetwork::Udp` retain separate winners. TCP uses the TCP probe average, or the `(member tag, check_url)` average when the group has a custom target. UDP first uses `DataUdp`, then `DnsUdp`; if no eligible candidate has UDP measurements, it mirrors the TCP selection instead of inventing a UDP ranking from missing data. This gives the effective fallback order `DataUdp → DnsUdp → TCP`.

The effective tolerance is `max(configured tolerance, 1 ms)`. The incumbent stays selected while:

`best latency + tolerance >= incumbent current measured latency`

The incumbent baseline is read again at selection time, not retained from the moment it won. A degraded incumbent can therefore be replaced; this matches sing-box `Select()` behavior. Hysteresis is skipped for an incumbent carrying failure strikes — a just-failed incumbent is replaced immediately.

Probe failures update only liveness and cooldown; they never create synthetic latency samples or ranking strikes. Real dial failures append a display-excluded synthetic 10-second placeholder plus one failure strike. Real history and moving average are retained, but a candidate with pending dial-failure strikes ranks below every non-demoted candidate. Strikes clear only after `max(strikes, 2)` consecutive real successes — this is the flap guard that stops a fast-but-flaky node from reclaiming first place with one lucky probe.

Real traffic also feeds ranking directly (TCP only). Each node keeps a self-referential EMA (α=1/8, after 3 warmup dials) of fresh dial latencies; pool-ready hits are excluded because they perform no network round trip. Three consecutive dials slower than `max(min(2×EMA, EMA+500 ms), 250 ms)` append one failure strike and fire an emergency probe; the 250 ms floor keeps a fast incumbent's normal load jitter (e.g. 60→120 ms) from tripping the detector. The probe moving average is never touched, and a false positive (a shifted target mix rather than node decay) self-heals when the emergency probe succeeds and consecutive probe successes clear the strike. Gradual drift stays owned by the probe cycle; UDP degradation keeps the probe-cycle plus `DataUdp` traffic-threshold handling.

When an authoritative single-candidate dial fails, the just-reported failure usually changes the plan, so the flow retries exactly once with the re-planned replacement — the failure is invisible to the client. A re-plan yielding the same first leaf (Selector pin, Fallback pin on a still-alive member, single-node outbound) is not retried.

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
| Periodic probe | 3 | 3 | 3 |
| Real traffic | 10 | 3 | 50 |

Probe and traffic failures have separate counters. Probe failures apply exponential cooldown from 5 seconds to 300 seconds. A separate `min(5s, check_interval)` recovery scheduler considers only dead domain/family states whose cooldown is due; deep-backoff states continue at the 300-second cadence rather than stopping permanently.

A dead state normally needs two consecutive probe successes to recover. `notify_network_change` clears stale cooldowns after a relevant link, address, or route change, primes dead states, and triggers probes so one fresh success can verify recovery. Newly registered nodes receive a 60-second grace period during which non-forced failures are recorded but do not count toward death. Probe history retains 100 entries per node, domain, and address family.

| Probe path | Behavior |
| --- | --- |
| TCP | Sends the configured HTTP method to `tcp_check_url` through the node, or performs a raw TCP connect when no HTTP probe applies. A cold reusable node first establishes its session/client in a throwaway runtime; setup is untimed, then only a completed HTTP exchange records warm-path RTT in the matching TCP family state. Setup and target-exchange failures both update liveness/cooldown without contributing latency or ranking strikes. |
| UDP health | Sends one minimal DNS query to the first `udp_check_dns` target through the node's own `dial_udp_transport`. Success records the measured RTT and marks both `DnsUdp` and `DataUdp` alive; failure adds one probe failure to each UDP domain. It never changes TCP state. |
| Honk QUIC score | Only with `honk-policy`, separately performs a real TLS-in-QUIC handshake with ALPN `h3` through a new packet transport for each node in a Honk group, targeting the first HTTPS `tcp_check_url`. Success or failure updates the exact `DataUdp` score and aggregate prior; it never changes liveness or awards unobserved byte volume. |
| Per-group URL | Probes the dynamically resolved `(member tag, current leaf)` pairs with the same throwaway warm-path timing as the global TCP probe. State is TCP-only, dies after three consecutive failures, and uses the same cooldown and two-success recovery. `sync_group_check_urls` replaces the active group/URL registry on reload. |

`has_udp_state` distinguishes a node with no UDP observations from one explicitly observed dead. Established endpoint send, receive, and reply-idle errors report `DataUdp` traffic failures. Intentional endpoint retirement, node-death cancellation, and process shutdown are health-neutral.

An alive-to-dead transition invokes the control-plane death callback, which purges the node's pooled connections and UDP endpoints so no stale reusable object is handed to new traffic.

The last real TCP delay sample per node is written to `cache.db` every 60 seconds and restored at startup only when it is at most 24 hours old. Liveness is never restored from the cache. Synthetic 10-second placeholders are flagged, excluded from display history and the moving average, and never persisted as the last real sample; selection demotion lives on the failure-strike counters, not on the placeholder.

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

On reload, unchanged node configurations transfer their existing `NodeRuntime`, including live AnyTLS, VLESS H2MUX/Mux.Cool, and QUIC state, to the replacement generation. The old generation becomes terminal to new warm work while active flows drain normally. Periodic HTTP health probes and on-demand Clash delay tests both warm a cold reusable session or QUIC client in a throwaway runtime before timing, then close it; a scan therefore retains no new per-member transport state. Only a successful post-warm target exchange reports health and contributes RTT to selection.

## Dial admission budget

`max_concurrent_dials` defaults to 64 and creates a generation-local semaphore for physical proxied connects and protocol handshakes. The configured value is clamped to the immutable process-wide descriptor gate computed at startup. Reload may change the replacement generation's local limit, but overlapping old and new generations still share that same process gate.

Ready-pool hits, logical streams opened on an already warm generation transport, and built-in `direct`/`block` dials are exempt. A bare-TCP pool hit still runs its protocol handshake and therefore remains admitted by the dial budget.

## Related docs

- [Outbound design](./outbound.md)
- [Control-plane design](./control-plane.md)
- [Group reference](../reference/groups.md)
- [Global reference](../reference/global.md)
