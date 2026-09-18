# Group Selection, Health, and Warm-up Design

This document explains how honk resolves groups to leaf outbounds, tracks their health, and retains bounded warm resources.

## Scope

The scope is `GroupManager`, `AliveDialerSet`, the always-compiled Score scorer, cold URLTest preparation, and the warm-resource coordinators. Group fields and policy syntax belong in the [group reference](../reference/groups.md); process-wide health, warm-up, and dial keys belong in the [global reference](../reference/global.md).

## Group manager and selection pipeline

`SharedGroupManager` is a stable, hot-swappable handle:

`SharedGroupManager = Arc<parking_lot::RwLock<Arc<GroupManager>>>`

A reload builds a complete replacement `GroupManager`, migrates Selector choices whose group and member tag still exist via `migrate_selector_choices_from`, installs interrupt, warm-up, and persistence callbacks before publication, and swaps the inner `Arc`. Readers therefore see either the old or the new manager, never a partially rebuilt graph.

The `src/group/` facade and its internals are split by responsibility:

| Module | Responsibility |
| --- | --- |
| `mod.rs` | `GroupManager` types, shared handle, and selection-plan entry points |
| `resolver.rs` | Nested-group expansion, member/leaf introspection, cycle cutting, and Selector-choice migration |
| `filter.rs` | Network- and family-specific liveness filtering |
| `policy.rs` | Selector, URLTest, LoadBalance, and Fallback picks and latency ranking |
| `score.rs`, `score/selection.rs` | Always-compiled target-aware Score state, evidence, reporters, counters, and candidate ranking/selection; `score/tests/` contains the scenario suites |
| `state.rs` | URLTest/Fallback caches, Selector choices, and callbacks |

Selection follows one invariant (sing-box semantics): after resolution and liveness filtering, the dial path uses exactly the policy pick. Selector returns its effective manual choice, URLTest its current winner, LoadBalance its next member, Fallback its pin, and Score its ranked eligible leaf, including deterministic cold exploration. The only multi-candidate exception at selection time is an unmeasured top-level URLTest group; all warm URLTest and non-URLTest plans are authoritative single-leaf plans. Post-failure retry racing belongs to `connection.rs`, not here, and parallel racing is added nowhere else. If a group with no `final` has exactly one unique leaf and TCP liveness excludes it, that same leaf remains an authoritative last resort only when reachable through the current Selector choices: its health stays dead, but a real dial can prove recovery without leaking to another member or `direct`. UDP keeps normal liveness exclusion. Last-resort serving logs a rate-limited warning (60s per group); warm-up peeks stay silent.

## Policy semantics

| Policy | Runtime behavior |
| --- | --- |
| Selector | TCP and UDP resolve the runtime choice, then `group.default`, then the first declared member independently of health; only missing/non-member tags fall through. No eligible candidate for that member invokes only the group's explicit `final` or the same-leaf TCP last resort above; without either, the plan is empty. GroupManager resolves finals at every nested level. The Clash API changes the runtime choice. `PersistCallback` stores effective writes in `cache.db` via honk-core's `cachedb`; when `interrupt_connections` is enabled, `InterruptCallback` removes tracking records but does not cancel live relays. Typed configuration diagnostics warn about this limitation. |
| URLTest | Chooses the lowest halving moving average, keeps independent TCP and UDP selections, applies tolerance hysteresis, and re-evaluates lazily on dial and selection queries. A real selection change may invoke `InterruptCallback`. |
| LoadBalance | Round-robins eligible members in declaration order. Every group owns independent `AtomicUsize` cursors for TCP and UDP. Rotation never invokes `InterruptCallback`. |
| Fallback | Pins the first eligible member in declaration order independently for TCP and UDP. The pin stays until that member dies; recovery of an earlier member does not cause failback. |
| Score | With `policy: score`, chooses one health-eligible leaf using observed reliability, fresh target-aware quality and bounded validation. Historical sample volume is not a performance bonus. Selector remains the default. |

### Score scoring and lifecycle

Score first runs the same liveness filter as every other policy. The filter's health family describes connectivity to the proxy server; the separately carried target family selects the scoring bucket. Consequently a server reached over IPv4 remains eligible for an IPv6 business target, while no score can return a node already excluded as dead.

The exact key is `(group, TCP/UDP, target IPv4/IPv6, normalized target, NodeId)`. Domains are ASCII-lowercased with one trailing dot removed and retain their port; IP targets retain the socket address. A second bounded `(group, TCP/UDP, target family or no family, NodeId)` aggregate supplies the prior for cold targets and receives targetless warm-up samples. Global aggregate, family aggregate, and exact-target evidence blend hierarchically until the more specific layer has enough evidence. Recursive selection carries the same target context and attributes the leaf outcome to every Score group traversed.

Business attempt and outcome evidence decays with a 30-minute half-life. Setup failures carry extra weight in the Beta confidence bounds. Initial evidence qualification requires four effective useful completions; ordinary candidates must also meet the existing reliability bounds, observed-failure band and streak gate. Fresh targeted business RX can retain earned qualification for 60 seconds from its event time, renewing an unexpired lease without adding completions. An expired or invalidated lease cannot be restored by RX alone while effective completions remain below four. Failure and reload invalidate the lease. Sparse candidates still receive bounded trials. Ordinary ranking, metric baselines and reliability comparison share this qualification rule; overlapping global/family/exact completion evidence is never added as independent samples, and reliability blending and hold maturity still use actual decayed counts.

Performance has its own event timestamps and bounded four-observation inertia. Each metric loses confidence after 60 seconds and expires at 120 seconds regardless of historical completion count. Configured probe RTT supplies a baseline; fresh comparable target response and directional goodput can override it. Probe RTT, setup and response latency are normalized within their own measurement scope, not pooled as interchangeable milliseconds. HTTP identity includes the normalized request URI and method; probe domain and health family remain distinct.

Ordinary first choice still uses group-relative utility. If that winner is already the incumbent, it stays. An ineligible incumbent can be replaced immediately; an eligible incumbent with an unresolved business failure also bypasses holding. Recovery uses actual business RX strictly newer than each applicable cell's last failure: either accepted live progress from a targeted Traffic reporter with setup and TX, or a successful bidirectional terminal outcome. Live progress also respects the failure/reload invalidation fence and captured cell incarnation. Setup-only work, TX-only activity, probes, warm-up and cancellation alone cannot manufacture recovery; cancellation does not retract already accepted RX. Historical failure counts, streaks and backoff still change only through the existing terminal settlement rules.

For a trained, eligible, recovered incumbent, every eligible trained challenger is compared against that same incumbent. Performance pairs require full confidence on both sides: exact response, existing family-preferred aggregate response, same-cohort probe, paired setup, then paired warm setup. Each throughput direction uses a shared exact or aggregate pair; both candidates retain the existing best-direction utility over that shared set. Observed reliability contributes only when both candidates meet the shared evidence-qualification rule. A gain must clear the existing margin, capped at `0.005`; its support is the maximum of separately decayed global/family/exact completion counts, never their sum. Sparse exact evidence cannot reduce mature protection. Missing or expired performance alone is not a gain; holding does not certify availability and existing bounded trials remain possible. There is no fixed residency timer or guarantee that every performance dimension improves.

`ScoreFeedback::start()` creates a cloneable `ScoreReporter` only when associated work starts. Setup and first response publish once at their observation time. Accepted TCP writes and successfully delivered UDP progress feed nonoverlapping, event-driven 1–10 second windows; a measured direction needs at least 64 KiB, with bidirectional flow progress and a response. Windows do not add Beta successes. Final settlement contributes at most one outcome and never adds already-published bytes again; dropping the last unfinished handle cancels. Rejection, cancellation and shutdown remove the attempt without a failure, while factual observations remain. Idle or application-limited traffic is not proof of congestion; no sampler task, payload replay or connection migration is added.

Business-RX publication is separate from throughput windows: the first eligible positive RX publishes immediately, then at most once per second per reporter. Only another positive RX call can publish live progress; no timer or TX-only callback flushes a suppressed receive. A post-failure receive inside the throttle interval can therefore wait for the next publishable RX or terminal settlement, not necessarily one wall-clock second. Live publications neither add Beta outcomes nor refresh terminal verification evidence.

Admission-scoped TCP dialing starts its reporter at the first admitted physical attempt or immediately before a logical open on a reused session or QUIC connection, not while waiting for cold physical admission. The callback is one-shot; completed paths without either boundary retain the completion fallback.

An unstarted scope's timeout is a local capacity refusal only while a physical-admission acquisition is still pending. DNS resolution before admission remains an ordinary timeout, allowing the existing eligible retry path. Classification inspects the scope before cancelling its future; cancellation removes only that acquisition's pending registration.

Ordinary and post-race TCP ready/bare refills retain setup-quality evidence, but their successes and failures never alter real-flow failure streaks or exploration backoff. UDP drivers classify their terminal result before their health callback can synchronously retire the endpoint, so that callback cannot turn an error into neutral cancellation or success. Intentional retirement remains neutral without a reply and successful after a reply; process shutdown and packet-local congestion stay neutral, and reply-idle expiry is a timeout only when no reply was received.

On live endpoints, a proven QUIC path stall takes precedence and remains a timeout even when the immediate error would otherwise be classified as packet-local congestion or idle-after-reply.

Traffic reporters cover transparent TCP/UDP, supported DNS exchanges and UI downloads. DNS attribution follows the carrier actually used, including TCP retry after UDP truncation. `HealthProbe` records configured measurement quality in global aggregate probe slots without settling business reliability or resetting real-flow streaks. `Warmup` records setup quality only. On-demand delay measurements retain their API/Alive latency history but do not create inert Score exchange reporters or convert failed arbitrary targets into real dial failures; their actual session preparation may still report warm-up quality.

Startup exploration has one finite group/network/target-family allowance: all candidates up to four, otherwise `ceil(sqrt(n)) + 1`. Later time/count/degradation opportunities share one reservation and are spent only on unresolved availability/response questions. A promising contender with real progress receives a focused run of at most eight trial selections; cancellation or no progress rotates opportunities rather than pinning the run. This lets sparse large-group candidates finish qualification before historical evidence decays. Fresh settled or near-equivalent cohorts stop forced sampling; expiry, contradiction or membership/probe changes create new gaps. The coarse bound remains 30 seconds or `clamp(2n,16,64)` selections, with degradation requiring at least 16 selections since the prior trial. Real failures retain 5-minute-to-6-hour backoff; only business success reduces the streak. Trials never acquire committed-incumbent protection, and three-failure exclusion does not permanently prevent backoff-expired recovery.

Score state is demand-driven, memory-only, process-local, and non-configurable. Exact cells use a 4,096-entry LRU and aggregate cells use a separate 4,096-entry LRU. Exact-target evidence is transport-quality evidence, not a semantic-unlock capability result; existing routing or geosite rules can select a dedicated service-specific Score group when that coarse cohort is desired. A successful in-process reload shares the same state `Arc`, publishes the new valid `(group, member)` set, and prunes removed cells; late feedback for deleted membership is ignored. Process restart clears everything. Score cells and scorer-only target data are never logged, persisted, or returned by Clash APIs; the existing `/connections` destination metadata remains unchanged.

Neutral cells remain in the bounded LRUs rather than being eagerly deleted while another reporter may still own their incarnation. Reload clears configured-probe baselines and rejects old-generation probe observations; admitted business flows may continue reporting for surviving membership and matching cell incarnations. Eviction never permits an old reporter to recreate a cell.

#### Conditional verification

The default objective is response quality with observed business-availability protection; directional goodput participates only when comparable evidence exists. Forwarding remains immediate, but a chosen leaf is not automatically a confirmed conclusion. `provisional` and `observedUsable` describe the selected path's business evidence; `unconfirmed`, `equivalent` and `supported` separately describe the named comparison basis. A 10% metric tolerance represents practical equivalence, not an error probability or a proof of global optimality. Confidence here is an empirical evidence threshold, not a time-uniform confidence sequence.

The same evaluator identifies missing availability, response and transfer evidence, chooses the next budgeted real-flow validation, and produces readonly API summaries. Exact-target claims cannot inherit aggregate or probe certification. Successful HEAD/QUIC probes can support only their configured measurement cohort, never target usability or bulk capacity. Unknown transfer yields `awaitTransfer`; no background bandwidth scan or copied user request is created. `nextBusinessFlow` means a future real-flow opportunity when the shared budget permits it, not already-dispatched I/O; `backoff` retains the failure fence.

Claims expire when their weakest supporting evidence crosses the full-confidence boundary (at most 60 seconds here), sooner if effective completion evidence or a supporting failure exclusion expires. Failed business outcomes and committed reload revoke recent usability without erasing long-term reliability. API reads derive current validity without advancing clocks, trials or counters. Authorized Apply records confirmations, expiry/contradiction transitions, validation selections and accumulated time to confirmation in existing bounded history; a confirmation may concern a probe comparison while business usability remains provisional. See [API semantics](../reference/api.md#score-verification).

Verification's recent usability remains terminal-based and is dated by the latest positive business RX, never by TX-only progress or terminal cleanup. A retained ordinary qualification lease or live recovery does not upgrade `scoreVerification`: it can remain provisional while an active incumbent is retained. Late completions retain their once-only lifetime outcome but cannot contribute expired RX or RX at or before the latest failure/reload fence to recent verification evidence. Unexpired out-of-order completions preserve the newest observation clock, and an admitted surviving flow may contribute genuinely new RX after that fence.

An authorized applied multi-candidate rank increments one final reason: `coldExplore`, `periodicExplore`, `incumbentIneligible`, `freshFailureBypass`, `insufficientEvidenceHeld`, `incumbentHeld`, `reliabilityWinner` or `performanceWinner`. `insufficientEvidenceHeld` means no challenger earned promotion and the ordinary utility winner lacked a fully qualified shared performance comparison; it does not claim that reliability history is absent. `ordinarySwitch` separately counts committed normal A→B identity changes within the same `(group, network, family, target)` history; first choices and trials do not count. `switchFlap` is its subset returning to the prior winner within eight ordinary selections. `deadFiltered`, `failStreakExcluded` and `exploreBackedOff` count affected candidates, not failed flows. History remains a 4,096-entry LRU; unknown/evicted history cannot prove a switch. Peek, proxy/stat reads, singleton bypass and last-resort selection remain neutral for these counters. Authenticated `/stats.score` exports only fixed group/network counters and the two evidence-cache occupancy/eviction totals, without scorer-private node/target/cell identities.

Clash represents a Score group as `type: "url_test"`, reports the current aggregate TCP winner in `now`, and rejects `PUT /proxies/{name}`.

### URLTest ranking and hysteresis

Latency uses a halving moving average:

`next = (previous + sample) / 2`

The first sample initializes the average. This is dae `min_moving_avg` behavior: recent changes matter quickly without making one jitter sample authoritative.

`SelectionNetwork::Tcp` and `SelectionNetwork::Udp` retain separate winners. TCP uses the TCP probe average, or the `(member tag, check_url)` average when the group has a custom target. UDP first uses `DataUdp`, then `DnsUdp`; if no eligible candidate has real UDP ranking evidence in either domain's retained moving average for the selected address family, it mirrors the TCP selection. Synthetic dial-failure samples alone do not disable this mirror; evicting real samples from the history ring does not erase retained ranking evidence. This gives the effective fallback order `DataUdp → DnsUdp → TCP`.

The effective tolerance is `max(configured tolerance, 1 ms)` (`group.tolerance.max(1)`). The incumbent stays selected while:

`best latency + tolerance >= incumbent current measured latency`

The incumbent baseline is read again at selection time, not retained from the moment it won. A degraded incumbent can therefore be replaced; this matches sing-box `Select()` behavior. Hysteresis is skipped for an incumbent carrying failure strikes — a just-failed incumbent is replaced immediately.

Probe failures update only liveness and cooldown; they never create synthetic latency samples or ranking strikes. Only two consecutive real dial failures append a display-excluded synthetic 10-second placeholder plus one failure strike — a lone transient failure (the retry race rescues that flow) leaves no selection state, and only a real dial success resets the streak, so a probe-alive but dial-dead node still accumulates. Real history and moving average are retained, but a candidate with pending dial-failure strikes ranks below every non-demoted candidate. Strikes clear only after `max(strikes, 2)` consecutive real successes — this is the flap guard that stops a fast-but-flaky node from reclaiming first place with one lucky probe.

Real traffic also feeds ranking directly (TCP only). Each node keeps a self-referential EMA (α=1/8, after 3 warmup dials) of fresh dial latencies; pool-ready hits are excluded because they perform no network round trip. Three consecutive dials slower than `max(min(2×EMA, EMA+500 ms), 250 ms)` (`max(min(2×ema, ema+500ms), 250ms)` in `report_dial_latency`) append one failure strike and fire an emergency probe; the 250 ms floor keeps a fast incumbent's normal load jitter (e.g. 60→120 ms) from tripping the detector. The probe moving average is never touched, and a false positive (a shifted target mix rather than node decay) self-heals when the emergency probe succeeds and consecutive probe successes clear the strike. Gradual drift stays owned by the probe cycle; UDP degradation keeps the probe-cycle plus `DataUdp` traffic-threshold path.

An authoritative URLTest setup failure retains its existing one retry round over the latency-ordered top three. A Score-owned setup instead permits one sequential different leaf, excluding the failed `NodeId` before ranking even when it remains the ordinary winner. Both Score attempts share one absolute establishment deadline and physical admission budget. Canonical resolution preserves Selector choices and only final-group edges actually traversed by the primary; display names never authorize fallback. Local typed refusal, pre-admission capacity exhaustion, cancellation and generation shutdown are terminal. No retry occurs after application payload is written.

A group `check_url` creates independent TCP-only liveness and latency state keyed by `(member tag, check_url)`. A failure removes that member only from groups using that target. Selector groups ignore `check_url` and emit a warning. URLTest probing sleeps after `idle_timeout`; an unset timeout uses the 30-minute health-layer default, and the next real selection wakes probes immediately.

## Nested groups and member identity

`Group.groups` names sub-groups. Each sub-group contributes exactly one candidate: the leaf selected by that sub-group's own policy for the current network and address family. The parent ranks or pins that candidate as one member rather than merging every descendant into its policy.

Resolution is bounded by `MAX_GROUP_DEPTH = 8` and a per-walk visited set. Construction also runs DFS over group edges and cuts every cycle-closing edge with a warning. These checks prevent a malformed graph from hanging selection or introspection.

Membership and explicit `final` edges share the bounded recursive resolver. A
subgroup with no eligible policy pick follows only its configured final; the
parent still sees that subgroup as the selected member. Final chains preserve
selection chains and Score attribution. Ordinary member/display lists exclude
final edges, while health registration, warm discovery, Score membership and
datapath connectivity use the reachable-final closure. A leaf health transition
recomputes every affected ancestor's alive slot, not only its first mapped group.
IPv6 health-family retries prefer a usable ordinary IPv4 proxy path before a
final, without changing the business target family. Missing or cyclic finals
remain refusals; no transport error or terminal packet rejection is retried here.

Selector captures a concrete node or sub-group member before candidate expansion and health filtering; repeated node tags bind the first matching declared `NodeId`. Parents retain the existing subgroup Peek, parent-health gate, and serving-commit order, so unchosen Score state is not advanced. For both TCP and UDP, a failed serving commit cannot restore the earlier peek; only a configured final may continue selection. Candidates retain their originating subgroup reference instead of rediscovering it from a display tag. A chosen automatic sub-group may still select a different leaf within its own membership. The sole TCP leaf's last-resort walk also respects every nested Selector choice, while explicit delay tests may inspect all members for recovery.

Display and API output retain member tags even when the physical dial reaches a deeper leaf; serving selection retains concrete node or subgroup identity separately:

| API | Output |
| --- | --- |
| `node_names_in_group` | Direct node tags plus sub-group tags |
| `leaf_node_names_in_group` | Deduplicated real leaf nodes reachable below the group |
| `delay_test_members` | One `(member tag, current leaf)` pair (`(tag, leaf)`) per effective member |
| `selection_chain` | Current chain from group through selected sub-groups to the leaf |

Custom-URL probes resolve `delay_test_members` again on every cycle. A sub-group is probed through its current pick, but the result is recorded under the sub-group tag. The parent therefore treats the sub-group as one stable member, matching sing-box RealTag semantics.

## Cold URLTest UDP preparation

Only a top-level URLTest plan with no usable measurement may prepare several UDP transports. Candidate starts use absolute offsets `0 ms`, `30 ms`, `80 ms`, then one every `80 ms`; at most three preparations are in flight. Absolute scheduling prevents an earlier slow attempt from shifting all later starts.

The first successful candidate that is still eligible wins. On a winner or deadline, honk aborts and drains every started loser before the scheduler returns; it then rechecks winner eligibility and commits protocol state before endpoint publication or the first application send. Only an observed preparation `Err` affects traffic health. Never-started work, cancellation, an ineligible successful result, and successfully drained losers are neutral; a completed error discovered while draining is still an observed error and counts. AnyTLS uses caller-owned provisional pool slots so losers never publish sessions. QUIC protocols build detached clients and publish only the finalized winner; losing clients are closed with their speculative work.

Authoritative single-node and cold URLTest plans share one absolute transport-preparation deadline of `max(10s, 4 × connect_timeout)`. It begins immediately before preparation and covers proxy-host resolution, physical-dial admission, protocol/control negotiation, stagger and full-capacity waits, plus the finalized winner's commit. Expiry starts no new candidate. Earlier sniffing/routing and later reply-socket creation, endpoint-driver readiness, and packet sends remain outside this deadline and retain their own lifecycle or I/O bounds.

## Health state and probes

`AliveDialerSet` keys node health, registrations, histories, emergency triggers, and latency collections by the node's `NodeId` UUID (`Uuid`). Display names are metadata for logs and probe lookup, not identity. Every node has six independent states: three domains across IPv4 and IPv6.

| Failure source | `Tcp` | `DnsUdp` | `DataUdp` |
| --- | ---: | ---: | ---: |
| Periodic probe | 3 | 3 | 3 |
| Real traffic | 10 | 3 | 50 |

Go dae's TCP=1 let transient probe loss eject URLTest incumbents through tolerance hysteresis.

Probe and traffic failures have separate counters. Probe failures apply exponential cooldown from 5 seconds to 300 seconds. A separate `min(5s, check_interval)` recovery scheduler considers only dead domain/family states whose cooldown is due; deep-backoff states continue at the 300-second cadence rather than stopping permanently.

A dead state normally needs two consecutive probe successes to recover. `notify_network_change` clears stale cooldowns after a relevant link, address, or route change, primes dead states, and triggers probes so one fresh success can verify recovery. Newly registered nodes receive a 60-second grace period during which non-forced failures are recorded but do not count toward death. Probe history retains 100 entries per node, domain, and address family.

| Probe path | Behavior |
| --- | --- |
| TCP | Sends the configured HTTP method to `tcp_check_url` through the node, or performs a raw TCP connect when no HTTP probe applies. `ProxyHttpProber` delegates HTTP execution to the shared outbound measurement path below and reuses a runtime only when `NodeRuntime::is_warm_or_stateless_for(WarmRequirement::Session)`; otherwise it closes a guarded cold runtime after the probe. Only a successful warm-path RTT enters the matching TCP family state; setup and target-exchange failures update liveness/cooldown without contributing latency or ranking strikes. |
| UDP health | Sends one minimal DNS query to the first `udp_check_dns` target through the node's packet path. It independently checks `NodeRuntime::is_warm_or_stateless_for(WarmRequirement::Udp)` and closes a guarded cold runtime when that requirement is not warm. Success records the measured RTT and marks both `DnsUdp` and `DataUdp` alive; failure adds one probe failure to each UDP domain unless the independent Score QUIC handshake succeeded in the same cycle, in which case only `DnsUdp` fails and `DataUdp` remains alive. It never changes TCP state. |
| Score QUIC evidence | Every periodic UDP cycle separately performs a real TLS-in-QUIC handshake with ALPN `h3` through each Score leaf, targeting the first HTTPS `global.tcp_check_url`. Its measured duration supplies separate `DataUdp` probe quality, never business successes or invented throughput. A successful handshake may revive `DataUdp` when DNS probing failed. Missing/non-HTTPS URLs disable this probe; non-Score leaves create neither this handshake nor Score cells. |
| Per-group URL | Probes the dynamically resolved `(member tag, current leaf)` pairs with the same throwaway warm-path timing as the global TCP probe. State is TCP-only, dies after three consecutive failures, and uses the same cooldown and two-success recovery. `sync_group_check_urls` replaces the active group/URL registry on reload. |

`has_udp_state(node)` distinguishes a node with no UDP observations from one explicitly observed dead. For an ordinary endpoint, terminal send/receive errors and reply-idle expiry without any reply report `DataUdp` failure after the driver captures its terminal per-flow Score outcome. For source-shared VLESS, the source owner reports transport health while every bound endpoint retains and settles its own Score reporter; matched replies belong to their endpoint, while foreign replies have no flow Score owner. A source terminal event retires its endpoints and fans the terminal outcome to those flows.

Typed policy, size, and `PacketRejection::Capacity` refusals are terminal for the candidate but health- and Score-neutral; CLI callers receive the capacity error rather than `NotApplicable`. Packet-local congestion, idle expiry after a reply, intentional retirement, node-death cancellation, and shutdown are also health-neutral. An alive-to-dead transition invokes the control-plane callback with `(NodeId, name)`, purging pooled connections and UDP endpoints. Skip UDP-domain death while its sibling UDP domain is explicitly alive, so a blocked `:53` probe does not purge working flows.

The last real TCP delay sample per node is written to `cache.db` every 60 seconds and restored at startup only when it is at most 24 hours old. Liveness is never restored from the cache. Synthetic 10-second placeholders are flagged, excluded from display history and the moving average, and never persisted as the last real sample; selection demotion lives on the failure-strike counters, not on the placeholder.

- `src/alive/` APIs include `register_node`, `notify_check_*`, `report_*_traffic`, and `record_dial_failure`. Group tables and `(member tag, check_url)` state remain name-keyed: groups have no NodeId; members may be sub-groups (sing-box RealTag).
  `mod.rs`: state, thresholds, registries, eBPF connectivity-push callback, `StickyCache`. `probe.rs`: HTTP/raw-connect `probe_node`, DNS-through-`dial_udp_transport` `probe_node_udp`, concurrent cycles. `collection.rs`: `DialerCollection` latencies, moving averages, and dial-failure tracking. `latencies.rs`: O(1), cap-10 ring; measurement `SystemTime` gives real Clash history times. `last_real_sample()` excludes synthetic entries, preventing bogus dashboard 10000ms.
- `src/urltest.rs` owns shared HTTP request construction and measurement; URL interpretation delegates to the canonical `honk-config::check` decoders. Core and generation URLTest also share explicit cold-session preparation, retaining fallible node admission before resources or feedback; standalone tool calls retain handler-owned setup and their outer CLI deadline. Requests use credential-free authority with non-default ports, omit fragments, and preserve raw path/query including dot segments; query-only URLs use `/?query`. HTTPS verifies certificates and negotiates `h2,http/1.1`, with server push disabled. A HEAD warm-up precedes the configured method (HEAD for delay tests), and both final responses must have valid decoded 200–499 statuses. HTTP/1 informational heads are consumed before the final response, except unsupported protocol switching; their cumulative size per round is capped at 16 KiB. HTTP/2 response header lists use the same size cap.
  Locally detected HTTP/2 protocol errors terminate the disposable probe connection on the first rejection; a later remote reset cannot turn rejected response headers into a warm-sample success.
  Cancelled-stream records use twice the per-round timeout, covering both request budgets so valid late warm-stream frames remain ignorable. At most two streams are retained, and completion or cancellation drops the connection without waiting for expiry.
  Every protocol reports the second request's warm-path RTT, excluding proxy dial, target TLS and session preparation. A second-round transport failure may return the validated first sample; HTTP/1 requires no partial response, and HTTP/2 accepts graceful GOAWAY or remote `REFUSED_STREAM`. Invalid/partial heads still fail. Cold reusable probes close their guarded runtime, and HTTP/2 drivers stop on completion/cancellation. Preparation, dial, TLS, HTTP/2 startup and each request have separate phase budgets; core retains its connection timeout. Empty delay URLs use `https://www.gstatic.com/generate_204`. `alive` owns health scheduling; only actual traffic feeds dial-failure strikes. Group delay concurrency remains capped at 10.
  The API's warm-up fallback is not published as Score evidence for the configured method: only a successfully measured second round updates that method's quality cohort.

Known upstream limitation: [`h2` 0.4.19 defaults a missing response `:status` to 200](https://github.com/hyperium/h2/issues/958). The probe validates the decoded status and cannot recover the omitted pseudo-header, so that malformed HTTP/2 response can appear healthy. This dependency fix is deferred pending upstream; no local fork or vendor patch is applied.

## UDP candidate eligibility

`filter_alive_candidates` decides UDP selection per node and address family:

- `DataUdp` alive or `DnsUdp` alive: selectable.
- Both UDP domains explicitly dead: excluded, even if TCP is alive.
- No UDP state has ever been recorded: inherit TCP liveness.

This keeps a TCP-healthy but UDP-broken node from attracting packet flows without penalizing deployments that have not enabled UDP probing yet.

## eBPF connectivity publication

The eBPF alive slot belongs to a group, not to one node. For every domain and address family, publication uses the OR of all reachable leaf-member states, plus the existing TCP admission exception for exactly one unique leaf and no `final`. A callback caused by one node transition recomputes that group value; it never writes the transitioning node's value directly. Admission does not override userspace selection: a chosen empty Selector path still refuses traffic even when this slot remains alive.

Reload first sets every slot needed by the old or new group layout to alive, making the transition fail-open. After the new routing generation is published, honk writes the exact new group snapshot. Reordered groups therefore cannot inherit stale ordinal state; if exact publication fails partway, unfilled transition slots remain fail-open rather than falsely killing a group.

## Warm-up and ownership

Warm-up has three independent mechanisms:

| Mechanism | Candidate and lifetime | Retained resource | Bounds |
| --- | --- | --- | --- |
| Startup preconnect | One startup-only pass; current group picks first, then config order. Only bare-TCP-poolable proxy nodes qualify. | One bare server TCP connection deposited in the pool | `'auto'` selects at most 8 nodes; `0` disables it. It owns no policy-retention bit. |
| Selector pin | Always tracks every Selector's configured leaf, including an unhealthy explicit choice; shared leaves are UUID-deduplicated. | The reusable session selected by the TCP path (AnyTLS or VLESS H2/shared Mux.Cool), one QUIC client/connection, or otherwise one bare server TCP | Effective-choice changes wake immediately; a 10-second pass repairs lost, consumed, or expired state. |
| UDP warm set | Opt-in; re-ranks each group's top `min(N, 3)` reusable UDP leaves for each address family on every pass, then UUID-deduplicates globally. | The reusable state selected by the UDP path, including a VLESS H2/shared/separate Mux.Cool pool, or a QUIC client | At most 4 warm attempts run concurrently; the retained process set is re-ranked and capped at `4 × N`. |

Selector and UDP ownership are independent bits on reusable node runtimes.
`WarmRequirement::Session` follows the TCP path and `WarmRequirement::Udp`
follows the UDP path, so a VLESS UDP-only pool does not change direct-TCP
warming or bare-TCP eligibility. Removing one owner leaves a shared pool retained
for the other; only the final applicable owner release drains future reuse.
Active flows are not cut. Startup preconnect remains only a pool seed.

On reload, unchanged node configurations transfer their existing `NodeRuntime`,
including AnyTLS, VLESS pools/source key, and QUIC state. Changed configuration
gets a fresh runtime. The existing outbound maintenance pass reaps unretained
idle VLESS carriers together with its other idle resources; no new protocol
timer is created.

## Dial admission budget

`max_concurrent_dials` defaults to 64 and creates a generation-local semaphore for physical proxied connects and protocol handshakes. The configured value is clamped to the immutable process-wide descriptor gate computed at startup. Reload may change the replacement generation's local limit, but overlapping old and new generations still share that same process gate.

Ready-pool hits and logical streams opened on an already warm generation transport are exempt. `block` never dials; `DirectHandler::dial` goes through `admit_physical_dial` like other physical connects. Datapath-offloaded direct flows and direct UI downloads through reqwest do not use this handler's gate. A bare-TCP pool hit still runs its protocol handshake and therefore remains admitted by the dial budget.

Each VLESS physical carrier also takes a permit from the startup-sized process
carrier gate shared by reload generations and DNS forks. The permit remains
held through provisional, active, draining, and idle carrier I/O until task
teardown. This global gate is authoritative; Mux.Cool does not impose a
second per-node two-carrier limit.

## Related docs

- [Outbound design](./outbound.md)
- [Control-plane design](./control-plane.md)
- [Group reference](../reference/groups.md)
- [Global reference](../reference/global.md)
