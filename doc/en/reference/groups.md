# Group reference

This page defines the current `group { ... }` configuration surface and member-selection semantics. A configuration may define at most 250 top-level user groups; higher routing ordinals are reserved by the ABI.

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
| `icon` | `icon` | `null` | Validated absolute HTTP(S) URL or data URI, at most 2048 characters; returned unchanged by native group reads, never guessed. |
| `filter: name(...)` | `filters` + `nodes` | `[]` | Select nodes by node name. The parser resolves matches to node UUIDs. |
| `filter: subtag(...)` | `filters` + `nodes` | `[]` | Select nodes by the current tag of the subscription that produced them. |
| `filter: group(...)` | `groups` | `[]` | Add nested group tags. Comma-separated arguments and pipe-separated tags are accepted. |
| `default` | `default` | `null` | Initial or fallback member tag for `selector`. |
| `final` | `final_outbound` | `null` | Node, group, `direct`, or `block` used when the group's policy has no eligible selection, including when that group is nested. Final nodes remain health-gated; missing or cyclic finals fail closed, never implicitly direct. |
| `check_url` | `check_url` | `null` | Per-group TCP health-check target for non-Selector policies. A Selector ignores it with a warning. |
| — (not in dae) | `check_interval` | `null` | Per-group interval field in seconds. The current runtime does not consult it and uses the global interval. |
| `tolerance` | `tolerance` | `50` | Nonnegative URLTest switch threshold in milliseconds. Without an explicit value, dae URLTest groups inherit `global.check_tolerance`; the runtime applies an effective minimum of 1 ms. |
| `idle_timeout` | `idle_timeout` | `null` | Nonnegative URLTest probe-suspension threshold after inactivity, in seconds. With `null`, the health layer uses 1800 seconds. |
| `interrupt_connections` | `interrupt_connections` | `false` | Close affected live userspace transports on selection changes, using captured group identities and network. This is transport retirement, not tracking removal; shared UDP carriers retain unaffected views. |
| — (not in dae) | `id` | random UUID | Internal group identity generated when the field is absent. |

## Policies

| Canonical name | Accepted dae spellings | Behavior |
| -------------- | ---------------------- | -------- |
| `selector` | `selector`, `select`, `fixed`, `fixed(0)` | Independently for TCP and UDP, uses that network's runtime choice, then `default`, then the first existing member before health filtering. Health never replaces a valid choice with a sibling. The choice may be a direct node or nested group. |
| `urltest` | `urltest`, `min_moving_avg`, `min_avg10`, `min_last_delay` | Selects the lowest-latency alive member using the halving moving average `(prev + sample) / 2` and tolerance; TCP and UDP selections are independent. |
| `loadbalance` | `loadbalance`, `roundrobin`, `round_robin`, `balance` | Round-robins over alive members with independent counters per group and TCP/UDP network. |
| `fallback` | `fallback` | Pins the first alive member in declaration order independently for TCP and UDP; recovery of an earlier member does not immediately fail back. |
| `score` | `score` | Always compiled; chooses one alive member using observed reliability, fresh target quality and bounded validation. TCP/UDP and target IPv4/IPv6 evidence remain separate. |

Policy matching is ASCII case-insensitive. The parser removes a parenthesized suffix when present before matching, which accepts `fixed(0)`. An unrecognized policy becomes `selector` and a diagnostic names the group. Legacy `honk` is invalid; use `score`.

Only missing or no-longer-member choices fall through to `default` or the first declared member. An existing chosen member without an eligible leaf does not fall back to a sibling, on either TCP or UDP: the only continuations are an explicit `final` or the same-leaf TCP last-resort rule below. A chosen nested group still applies its own policy, so URLTest may select another leaf inside that group.

Each selected subgroup resolves its own explicit `final` before returning an empty result to its parent. This is not permission to choose a different Selector sibling or retry a terminal protocol refusal. For IPv6 targets, an ordinary selected leaf reachable through IPv4 proxy health is tried before a final route.

When distinct nodes share a display tag, name-based defaults and Clash writes bind the first matching member in declaration order before health filtering. Native member IDs can select a particular direct member. Health cannot retarget either choice to a healthy same-name sibling.
Named `final` nodes likewise resolve the first matching configuration declaration; a healthy duplicate cannot replace it. Selection and final-node health registration use that same identity.

Native `PUT /api/v1/groups/{groupId}/selection` accepts a direct `member_id` and `network: "tcp"|"udp"|"both"`. Both-network changes validate and publish together; Clash selection writes both and displays TCP. Per-network choices are retained by reload/persistence, and interruption is acknowledged only after actual closes. Native automatic-policy pin/clear remains unavailable.

Restricted native Group PATCH edits parser-owned source spans only when the group's accepted source is writable. It supports policy, default member, final, tolerance, idle timeout and interruption—not icon, name or filters—and uses the quoted accepted group/config revision independently of source disk hashes. Full validation, durable write and reload still apply; a write is not activation success. See the [group API contract](./api.md#nodes-and-groups-m3).

If a group has exactly one unique leaf, no `final`, and that leaf is excluded by TCP health, honk can still dial the same leaf as a last resort, but only if the current Selector choices lead to it. This cannot bypass a chosen empty sub-group or imply a `direct` fallback. The node remains marked dead until real traffic or probes recover it; UDP keeps normal dead-member exclusion. Last-resort serving logs a rate-limited warning (60s per group).

Every configured Selector TCP proxy leaf stays warm. After resolving its TCP choice, honk retains a reusable multiplexed session, a QUIC client, or one bare server TCP connection according to the leaf protocol; `direct` and `block` need no warm resource. The separate UDP warm set follows UDP selection.

### Score policy

`policy: score` explicitly enables Score; it is always compiled and has no runtime tuning fields. An omitted policy remains `selector`. Reliability protects admission, but additional historical successes alone do not exclude a less-sampled, validated faster node.

Score chooses one authoritative leaf after ordinary health filtering. Proxy-health family is independent of business-target family. Normal ranking, performance baselines and incumbent protection share eligibility; sufficiently observed candidates compare actual failure risk and fresh performance rather than the most-sampled node's lower bound. Sparse evidence gets bounded trials. Configured probe quality is a baseline, not an infallible judge: fresh trustworthy target evidence can override it. Equal values use declaration order and stable identity.

The finite startup allowance covers every candidate up to four, otherwise `ceil(sqrt(n)) + 1`. Subsequent validation opportunities exist after 30 seconds, `clamp(2n,16,64)` selections, or observed degradation after at least 16 selections since the last trial, but are spent only on unresolved evidence gaps. A progressing promising contender gets at most eight focused trial selections; no-progress/cancelled work rotates fairly. Triggers share a `(group, TCP/UDP, target family or none)` budget; Peek and new targets cannot mint opportunities, and fresh equivalent cohorts stop forced sampling. Exploration does not acquire ordinary incumbent protection. Real failures retain exponential backoff and three-failure normal exclusion, while backoff-expired recovery trials remain possible.

Business reliability retains its 30-minute half-life. Performance confidence ages independently and expires after 120 seconds regardless of sample count. Setup and first response publish immediately; accepted transfer progress uses nonoverlapping 1–10 second windows with at least 64 KiB in the measured direction, bidirectional flow progress and a response. Windows never multiply terminal successes or failures. Goodput is workload-dependent, not link capacity; silence is not congestion. Mature switching protection is `0.005` after eight effective completions, using the maximum separately decayed support across applicable layers. Ineligible incumbents and unresolved business failures bypass holding; recovered historical failure mass alone does not. Healthy incumbent promotion requires qualified common performance or supported observed-reliability gain rather than missing-data bonuses. These experimental constants are not configurable; see [the lifecycle design](../design/groups.md#score-scoring-and-lifecycle).

Targeted Traffic RX after setup and TX can restore ordinary incumbent protection before the flow ends, without clearing failure streaks or adding terminal successes. The first eligible RX publishes immediately; subsequent publication is event-driven and capped at once per second per reporter, so a suppressed receive needs another publishable RX or terminal settlement. Four effective useful completions plus fresh business RX can earn a 60-second qualification lease; RX within that lease can renew it without inflating evidence counts. Failure/reload invalidates the lease, and below-threshold candidates cannot regain an expired lease from RX alone. These ordinary-selection rules do not relax the terminal-evidence requirements of `scoreVerification`.

Business scores remain scoped by group, transport, target family, normalized target and node identity. Global/family/exact reliability is blended without adding overlapping completions. Target performance overrides its baseline only while fresh and comparable. Probe RTT has separate protocol/family and normalized HTTP URI/method identity; warm-up supplies setup quality only. Nested paths attribute a real outcome once to every traversed Score group.

Transparent TCP/UDP, supported DNS exchanges and UI downloads report actual business attempts. Configured HTTP/UDP/QUIC probes provide fresh quality without adding business successes or clearing traffic streaks. Manual Clash delay measurements retain their Alive/API history but do not feed a configured Score baseline or turn arbitrary target failure into real-dial demotion. Actual preparation remains warm-up evidence. Independent Score QUIC handshakes preserve existing DataUdp health recovery without invented byte volume.

Sustained measured carrier pressure may reopen bounded comparison without adding business failures or directly changing the winner. This is honk-to-proxy advisory evidence, not end-to-end UDP loss or a first-request guarantee; unsupported paths remain unknown. See [carrier-pressure scope](../design/groups.md#score-scoring-and-lifecycle).

Score state is memory-only and process-local, with one 4,096-entry LRU for exact node-target cells and another 4,096-entry LRU for aggregate cells. Exact-target evidence measures observed transport quality, not whether a service is semantically unlocked; use existing routing or geosite rules to select a dedicated service-specific Score group when that coarse cohort is needed. A successful in-process reload shares the same state and removes cells for deleted groups or members; process restart clears it. Score cells and scorer-only domain/IP keys are never logged, persisted, or returned by Clash APIs. Established connection metadata is unaffected.

After a retryable TCP setup failure, a Score-owned request may try one different permitted leaf even if ordinary ranking still prefers the failed node. Both attempts share a deadline and existing dial admission. Selector boundaries and actual primary final-edge provenance remain authoritative; no new direct/final route or application payload replay is introduced. A committed reload invalidates probe baselines while retaining valid in-flight business evidence; neutral cells stay within the existing bounded LRUs.

Each authorized applied multi-candidate rank records one exclusive reason: `coldExplore`, `periodicExplore`, `incumbentIneligible`, `freshFailureBypass`, `insufficientEvidenceHeld`, `incumbentHeld`, `reliabilityWinner` or `performanceWinner`. `ordinarySwitch` counts committed same-scope A→B changes, excluding first choices and trials; `switchFlap` counts the subset returning to the previous winner within eight ordinary choices. Candidate filtering/backoff counters remain separate. Peek and display/API reads are neutral. Authenticated `/stats.score.groups[]` exposes only fixed group/network counters; `/stats.score.cache` describes the two bounded evidence LRUs. See [API reason semantics](./api.md#score-selection-reason-fields); no scorer-private node or target identities are exported.

For Clash compatibility, Score remains automatic but is represented as `type: "url_test"`; `now` is the current aggregate TCP winner, and `PUT /proxies/{name}` is rejected.

Sampling resolves explicit availability/response gaps within the shared budget, with at most eight focused trials for a progressing contender. Fresh equivalent cohorts stop forced sampling, and missing transfer waits for real offered load. Additive `scoreVerification` summaries distinguish provisional forwarding, observed usability, limited comparisons, evidence scope/expiry and next action; see [API verification](./api.md#score-verification). These are retractable empirical conclusions, not a guarantee of best-arm identification or future network behavior.

## Filter resolution

1. A standalone `group('tag')` line adds nested tags to `groups`; it is not evaluated as a node predicate. A nested tag may contribute the leaf selected by that group's current policy. A `group(...)` line containing another predicate or trailing text is reported as a diagnostic and ignored; a group whose only filter is such a line remains empty.
2. `name(...)` matches `Node.name`. `subtag(...)` maps `Node.subscription_id` to the current subscription tag and matches that tag. Plain arguments are exact matches, `keyword:` is a substring match, and `regex:` is a raw regular expression. Matching is case-sensitive; multiple arguments in one predicate are alternatives.
3. Predicates joined by `&&` on one line are AND-ed. Prefixing a predicate with `!` negates it. Separate `name(...)` and `subtag(...)` `filter:` lines are OR-ed; standalone `group(...)` lines add nested candidates.
4. Filter-derived membership is rebuilt after every subscription refresh. Stable node UUIDs therefore do not retain stale membership after their subscription provenance changes.
5. A group with neither node filters nor nested groups receives all current nodes. Explicit `group()`, an empty filter, an empty nested group, or a filter emptied by subscription refresh selects nothing. Empty contributions remain explicit through JSON/YAML/TOML round-trips and refresh; valid sibling filters still contribute by OR, and `final` remains independent.

A filter honk cannot parse is ignored and reported by its ordinal among the group's node filters, excluding only nonempty standalone `group(...)` lines; mixed lines are counted. `group()` emits `empty-subgroup`. Remove the filter for all nodes; explicit `group()` now selects none. The injected `direct` and `block` are outbounds, not pool members: an unfiltered group, `keyword:`, `regex:` and `subtag(...)` never select them, and only a filter that spells the name exactly (`filter: name(direct)`) admits one.

## Nested groups

Nested selection is depth-capped at 8. When the group manager builds the graph, it removes each cycle-closing edge and logs a warning; an unknown nested tag contributes no candidate. Each nested group contributes the single leaf selected by its own policy, so every dial ultimately resolves to one node.

Clash-facing group output preserves member tags: the `all` field lists direct node names and nested group tags rather than expanding nested groups. Leaf-facing health and connectivity traversal expands the real nodes below those tags.

## Related docs

- [Node reference](./nodes.md)
- [Routing reference](./routing.md)
- [Group design](../design/groups.md)
