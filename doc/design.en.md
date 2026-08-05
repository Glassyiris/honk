# honk Design Document

> Inspired by [dae](https://github.com/daeuniverse/dae) (eBPF transparent proxy datapath) and [sing-box](https://github.com/SagerNet/sing-box) (outbound groups, protocols, Clash API).
>
> This document describes architecture as implemented in the current tree. Prefer source + this doc over older notes in `plan.md` when they disagree.

## 1. Goals

- Provide a **Linux eBPF transparent proxy** that intercepts LAN/WAN traffic with low overhead.
- Keep a **dae-compatible configuration surface**: the native `.dae` syntax is the primary (and only documented) configuration format.
- Offer a **sing-box-like outbound stack**: multi-protocol handlers, Selector / URLTest / LoadBalance / Fallback groups, health checks, Clash-compatible control API.
- Ship as an **engine-only** binary (`honk-core`). The GraphQL API and Leptos dashboard crates were removed.

## 2. Non-goals (current)

- Full Clash Meta / mihomo feature parity (FakeIP engine and remote rule-sets).
- Windows / macOS transparent proxy.

## 3. Inspiration map

| Area | Primary influence | Notes |
| ------ | ------------------- | -------- |
| TC classify + match_set routing | **dae** | `ROUTING_MAP` MatchSets, LPM tries, domain bitmaps, must/OR/AND |
| `dae0` / `dae0peer` + netns delivery | **dae** | Isolated `daens`, sk_lookup / SockMap, reply rewrite |
| Process matching via cgroup cookie→pid | **dae** | `COOKIE_PID_MAP` |
| DNS learning into domain routing maps | **dae** | Userspace notify → `DOMAIN_ROUTING_MAP` |
| Config section syntax | **dae** | `global { } node { } group { } routing { }` |
| Group policies & nested outbounds | **sing-box** | Selector / URLTest / LB / Fallback, RealTag-style chain |
| TCP/UDP separate URLTest picks | **sing-box** | Tolerance, idle_timeout, interrupt_connections |
| Clash API + external UI download | **sing-box** clashapi | Minimal REST/WS set |
| Protocol/transport details | **sing-box** + daeuniverse **outbound** | SS2022, AnyTLS pool, UoT v2, Hy2/TUIC/Juicity |

## 4. Crate layout

```text
crates/
├── honk-config         # Schema + dae-syntax parser + share links
├── honk-ebpf-common    # no_std #[repr(C)] types shared kernel ↔ userspace
├── honk-ebpf           # Kernel programs (excluded from workspace; bpfel-unknown-none)
├── honk-outbound       # Proxy handlers, groups, AliveDialerSet, URLTest
└── honk-core           # Engine binary: control plane, DNS, relay, Clash API, eBPF attach
```

```mermaid
flowchart TB
  CFG[honk-config] --> CORE[honk-core]
  CFG --> OB[honk-outbound]
  CORE --> OB
  CORE --> COM[honk-ebpf-common]
  EBPF[honk-ebpf] --> COM
  CORE -->|embeds object| EBPF
```

**ABI rule:** any change to map keys/values or constants must update both `honk-ebpf-common` and `honk-ebpf` (and the userspace map writers in `honk-core`).

## 5. High-level data path

```mermaid
flowchart TB
  subgraph Client
    APP[LAN / local app]
  end

  subgraph Host
    TC[TC lan/wan ingress+egress]
    MAPS[MatchSets + handoff maps]
    DAE0[dae0 veth 169.254.0.1]
  end

  subgraph daens
    PEER[dae0peer]
    SK[sk_lookup + LISTEN_SOCKET_MAP]
    LISTEN[IP_TRANSPARENT listeners]
  end

  subgraph Userspace
    CP[ControlPlane]
    SNIFF[SNI / HTTP Host / QUIC SNI]
    R[Router fallback]
    G[GroupManager → leaf node]
    D[TcpOutbound dial]
    REL[relay splice / copy / UDP]
  end

  APP --> TC --> MAPS
  MAPS -->|proxy / need userspace| DAE0 --> PEER --> SK --> LISTEN --> CP
  CP --> SNIFF --> R --> G --> D --> REL
  REL -->|SO_MARK bypass| WAN[WAN egress]
  REL -->|UDP anyfrom replies| PEER
```

### Packet walk (simplified)

1. **TC ingress** on `lan_interface` (L2 or L3 by interface type) parses the packet and runs the eBPF route loop.
2. DNS to port 53 takes a **fast path** (skip expensive match loop) and is redirected to the control plane.
3. Outcomes:
   - `direct + must` → leave on host stack (no redirect).
   - `direct` without must / user outbound / block / control-plane routing → redirect into `dae0` when the outbound is considered alive.
4. In **daens**, `sk_lookup` assigns the flow to transparent TCP/UDP listeners.
5. **Userspace** takes the routing handoff, optionally sniffs domain, falls back to the full `Router`, applies Clash mode override, selects a group leaf, dials, and relays.
6. Dial/probe/DNS-upstream sockets use **`DAE_BYPASS_MARK` (`0x100`)** so eBPF does not re-proxy control-plane traffic.
7. UDP replies use per-endpoint **anyfrom** transparent sockets (dae parity) so source addresses stay correct on the way back through `dae0_ingress`.

Startup admission is fail-open until the listener generation is complete: TC hooks
leave traffic untouched while `DATAPATH_STATE_MAP[0]` is zero. Userspace publishes
every TCP/UDP listener FD, starts the receive loops, then opens that single gate;
shutdown closes it before listener teardown. A partial SockMap publication can
therefore never redirect a flow into a missing listener slot.

> **Note:** Older docs mentioned host `iptables TPROXY` on the bridge master as the primary path. The live path is **TC redirect + daens + sk_lookup**. Listeners are still `IP_TRANSPARENT`. Cleanup scripts may still remove leftover legacy iptables rules.

## 6. eBPF design

### Programs

| Program family | Hook | Role |
| ---------------- | ------ | ------ |
| `lan_ingress_l2/l3` | TC ingress LAN | Classify, route, redirect, TX stats |
| `wan_ingress_l2/l3` | TC ingress WAN | WAN-side / reverse path (dual-homed) |
| `tproxy_lan/wan_egress_*` | TC egress | Local-originated traffic + reverse conn state |
| `dae0_ingress` | TC ingress dae0 | Reply rewrite + RX stats |
| `dae0peer_ingress` | TC ingress dae0peer | Delivery assist in daens |
| `tproxy_sk_lookup` | sk_lookup | Map flows onto listeners |
| cgroup sock/connect/sendmsg | cgroup | Cookie → pid/comm for `pname` rules |

### Key maps

| Map | Role |
| ----- | ------ |
| `ROUTING_MAP` + `ROUTING_META_MAP` | MatchSet array + L4/IP-version bitmaps; two-phase publish |
| `DEST/SOURCE/MAC_LPM_ROUTING_MAP` | LPM tries for CIDR/MAC |
| `DOMAIN_ROUTING_MAP` | IP → domain-rule bitmaps (DNS-learned) |
| `ROUTING_HANDOFF_MAP` | Tuple → userspace handoff |
| `REDIRECT_TRACK` / `CONN_STATE_MAP` | Redirect + conntrack state |
| `BPF_STATS_MAP` | Conn-state overflow plus redirect/handoff/cookie insert failures |
| `OUTBOUND_CONNECTIVITY_MAP` | Alive bits pushed from userspace health checks |
| `OUTBOUND_STATS` | Per-CPU tx/rx packets/bytes per outbound |
| `LISTEN_SOCKET_MAP` | SockMap of transparent listeners |
| `DATAPATH_STATE_MAP` | Admission gate opened only after the complete listener generation is published |
| `EVENT_RINGBUF` | Overflow events drained to tracing |

### Reserved outbound indices

Aligned with dae-core:

```text
0 Direct | 1 Block | 2+ user groups
0xFC MustRules | 0xFD ControlPlaneRouting | 0xFE OR | 0xFF AND
```

### Domain routing split brain

- **At SYN time**, pure domain rules often cannot match without a prior DNS learn or userspace sniff.
- DNS answers update `DOMAIN_ROUTING_MAP` so subsequent TCP can match in eBPF.
- `direct` without `must` is intentionally sent to userspace so SNI/HTTP Host can refine the route (dae-like).
- TCP SNI/HTTP Host and QUIC Initial SNI both re-run the userspace Router for non-`must`, non-`block` handoffs in domain-aware modes.

## 7. Userspace control plane

`honk-core` owns:

| Subsystem | Responsibility |
| ----------- | ---------------- |
| Netns / veth setup | Create `daens`, `dae0`/`dae0peer`, addresses, policy routing |
| `EbpfBackend` | Load/attach programs, push maps, stats, mock backend for tests |
| Accept loop | Transparent TCP/UDP, original destination, handoff take |
| `Router` | Full condition set (domain/geoip/geosite/process/…) |
| Sniffing | TCP SNI/Host, QUIC SNI |
| DNS | Cache, routing, forwarder, optional SQLite persist |
| Groups / dial | Via `honk-outbound` |
| Relay | `splice(2)` zero-copy when both ends are plain TCP; else `copy_bidirectional`; PacketTransport-backed UDP endpoint drivers |
| Clash API | Optional axum server |
| Cache DB | Selector choices, mode, optional DNS answers |
| Subscriptions | Fetch + periodic merge without rewriting the config file |

Plain-TCP splice requests at most 64 KiB for each direction's private
nonblocking pipe (128 KiB and four pipe FDs per full-duplex relay). Unsupported
splice paths fall back losslessly before moving bytes.


### Dial modes (`global.dial_mode`)

| Mode | Behavior |
| ------ | ---------- |
| `ip` | Resolve locally; dial by IP; sniffing off |
| `domain` | Sniff domain; verify it resolves to dest IP; dial with domain |
| `domain+` | Like `domain` but skip reality check of sniffed name |
| `domain++` | Force sniff and re-route on sniffed domain |

### UDP endpoint pipeline

**Destination provenance is fail-closed.** The shared IPv4/IPv6 receiver uses a valid
`ORIGDST` control message as authoritative. If it has no `ORIGDST`, only an exact
DNS query plus a specified `PKTINFO` destination may form `IP:53`; otherwise it
may use only a non-wildcard local bind. Malformed, duplicate, truncated, or
unspecified `ORIGDST`/`PKTINFO` metadata is rejected rather than downgraded, and
a packet without provenance is dropped before it can reserve an endpoint or send.

**`PacketTransport` is the only UDP contract.** `PacketOutbound::dial_udp_transport`
returns a framed, bidirectional transport for each endpoint. Tunnel handlers frame
packets directly on their tunnel. A SOCKS5 transport keeps its TCP UDP-ASSOCIATE
control stream for the association lifetime, frames and parses RFC 1928 UDP
packets, and treats control EOF as endpoint failure. Its connected UDP socket uses
the physical `BND.ADDR` relay, while `relay_addr()` and the received peer exposed
to the endpoint are the logical target peer used by first-reply filtering.

**Endpoint creation is transactional.** A `(client, original-destination)` mapping
first publishes an `Initializing` generation with a lease. After route/selection
preparation has one final eligible transport and an anyfrom reply socket, the
driver reaches its ready barrier, the lease commits `Ready`, the retained first
packet is sent and acknowledged, and only then do FIFO followers run. The receive
loop only routes/reserves/enqueues; it never awaits transport I/O. The dedicated
driver owns the first send, follower sends, and replies. A first or steady send has
a five-second timeout; a timeout or error is ambiguous, so the packet is never
replayed through another candidate.

**Queue and process budgets are ownership bounds.** A flow retains at most 64
datagrams, including the first, and all flows together retain at most 8 MiB of
payload. Slow admission and flow/global permits are acquired before payload
allocation or copy; followers are FIFO and nonblocking saturation drops the
newest packet. TCP, cold non-DNS UDP, and port-53 work have independent
admission semaphores, so one class cannot exhaust another. UDP endpoint slots
also reserve process FDs: production uses at most
`min(8192, (min(RLIMIT_NOFILE, 16384) - reserves) / 2)` endpoints. Removal
notifications use a bounded queue with deduplicated compensation. Reload
cancellation is epoch- and generation-fenced: it drains `Initializing` leases
and their resources, preserves already-`Ready` endpoints, and removes only the
same generation so an older task cannot erase a replacement.
Group ordinals also share eBPF connectivity slots. Reload first makes all transition
slots fail-open, switches the routing generation, then publishes the exact per-group,
per-network alive snapshot so reordered groups cannot inherit stale health.

**Selection races are deliberately narrow.** Normal selector, load-balance,
fallback, explicit-node, and warm-URLTest plans are authoritative single-leaf
plans. Only a top-level cold URLTest plan may prepare several eligible leaves:
absolute starts are 0/30/80 ms and then every 80 ms, with at most three in flight.
LoadBalance cursors and Fallback pins are independent for TCP and UDP, so traffic on
one network cannot advance or repin the other network's authoritative choice.
The first still-eligible success wins; started losers are aborted and drained before
binding. Only an observed preparation error affects traffic health; cancelled or
successfully drained speculative losers are health-neutral. AnyTLS uses a caller-owned,
cap-counted provisional session slot on this path rather than its normal pool-owned
dial task. A loser closes its detached session synchronously; only the finalized winner
commits into the captured runtime-generation pool and starts that pool's janitor, before
any endpoint publication or application send.

**UDP warm-up is opt-in and generation-owned.** `global.udp_warm_node_count`
defaults to 0, which creates no coordinator work or warm metrics. With a positive
budget, discovery peeks authoritative DataUdp group plans in V4 then V6 order,
UUID-deduplicates eligible configured leaves, and applies the budget; direct,
block, and cold URLTest plans are excluded. Dispatch has a maximum of four tasks.
AnyTLS owns the reusable pool in its runtime generation. Reload makes the old
generation terminal to new warm/speculative work, but existing TCP streams and Ready
UDP endpoints keep their sessions; after the old DNS runtime's leases and transports
retire, its pools reject new opens and close each session only when its last stream
releases. Only `Ready` and `AlreadyReady` are warm successes. Direct, other non-AnyTLS, and
currently deferred QUIC warm-up return `NotApplicable`, not a false success.

## 8. Outbound stack

### Handlers (`honk-outbound`)

Registered protocols: Direct, Block, SOCKS5, Shadowsocks (+ 2022), Trojan, VMess, VLESS, Hysteria2, TUIC, Juicity, AnyTLS.

Shared layers:

- `transport.rs` — TCP → optional TLS → WS / gRPC; a node with REALITY parameters takes the REALITY handshake here instead of plain TLS
- `quic.rs` — shared quinn client for Hy2 / TUIC / Juicity
- `tls.rs` — BoringSSL TLS and Chrome-fingerprint helpers
- `reality.rs` — REALITY client handshake (see below)

VMess and VLESS are compiled behind honk-outbound's `rprx` cargo feature (on in honk-core's default build); without it those nodes parse but dials are refused with "No handler for protocol".

### REALITY client

`honk-outbound/src/reality.rs` implements the REALITY handshake for VLESS/VMess outbounds, byte-compatible with Xray-core `transport/internet/reality/reality.go`, over two client hooks carried by a small boring-sys fork patch (`SSL_set1_client_x25519_private_key` presets the ephemeral X25519 key into the ClientHello key_share; `SSL_set_client_hello_fixup_cb` allows rewriting the serialized ClientHello in place before it enters the transcript):

- The legacy session_id is rewritten to `AES-256-GCM(authKey).Seal([ver:3][0][timestamp:4][short_id:8])`, where `authKey = HKDF-SHA256(X25519(client ephemeral, server public key), salt = client_random[:20], "REALITY")`, the nonce is `client_random[20:32]`, and the AAD is the whole ClientHello with the session_id slot zeroed.
- Server authentication replaces PKI (the mask target's real certificate would always fail it): a genuine REALITY server presents an ephemeral ed25519 certificate whose signature equals `HMAC-SHA512(authKey, raw ed25519 public key)`. Anything else — a real certificate relayed from the mask target when the session_id did not decrypt, a wrong key, a MITM — is fail-closed.
- Chrome mode is aligned against a real Chrome ClientHello: the reality-mode JA4 is `t13d1516h2_8daaf6152771_01adaf6b9c20` with ja4_a/ja4_b identical to real Chrome; the one known difference is ja4_c, because the signature-algorithm list must be widened with ed25519 (BoringSSL otherwise rejects the REALITY ephemeral leaf with WRONG_SIGNATURE_TYPE before authentication can run). ALPS is pinned to the old `0x4469` codepoint, closer to real Chrome than uTLS. Session resumption is never offered.
- The REALITY `dest`/SNI target must serve a TLS Certificate message under 8 KiB (sing-box reality buffers 8192 bytes): `dl.google.com` works, `www.microsoft.com` (8273 B) does not.

With `flow: xtls-rprx-vision`, the VLESS request carries the flow in the Xray `encoding.Addons` protobuf; the response header is stripped lazily on the first read (servers piggyback it on the first downstream bytes), and Vision response frames (`[command][contentLen u16][paddingLen u16]`) are unpadded on the read side — `command=2` (XTLS direct copy) switches the read side to the raw TCP socket when the server abandons the outer TLS session, while the write side stays on the outer stream.

### Groups

Policies (sing-box shaped):

| Policy | Behavior |
| -------- | ---------- |
| **Selector** | Manual pin; Clash API + cache persistence |
| **URLTest** | Lowest latency + tolerance vs the incumbent's current measured latency (sing-box parity); separate TCP/UDP selections; idle sleep; dial failure clears the node's latency history so the next connection re-selects; optional per-group `check_url` probed and ranked independently of the global target. Only an unmeasured top-level UDP URLTest plan is a staggered multi-candidate preparation; a warm selection is authoritative. |
| **LoadBalance** | Per-group round-robin among alive members |
| **Fallback** | First alive in declaration order; sticky until death |

Nested groups (`groups` field) flatten recursively (depth ≤ 8) to a single leaf on the dial path.

### Health (`AliveDialerSet`)

- Per-node states: TCP / DnsUDP / DataUDP × v4/v6
- Concurrent probes (default batch 10), recovery hysteresis, grace period, exponential backoff (deep-backoff nodes keep probing on the slow max-cooldown cadence — never a full stop)
- TCP: HTTP HEAD or raw connect; UDP: DNS query through the node’s own `dial_udp_transport`
- Pushes connectivity into eBPF so dead outbounds are not redirected

## 9. DNS design

```text
Client :53 → eBPF DNS fast path (redirect, no full route loop)
          → DnsController → cache → DnsRouter → UpstreamPool
          → answer + optional DOMAIN_ROUTING_MAP update
          → anyfrom reply
```

- Userspace cache only today (no kernel DNS answer cache map yet).
- Upstream protocols: UDP/TCP/DoT/DoH/DoQ/DoH3 are all implemented (`honk-core/src/dns/transport/`, pooled sessions with one retry after invalidation).
- Optional `outbound` on an upstream routes queries through a proxy node/group (anti-pollution intent; UDP+proxy is intentionally carried as TCP-DNS by the upstream policy; SOCKS5 RFC 1928 UDP remains a complete, independent transport; DoQ/DoH3 are direct-only).

Resolution defaults to `both`: an omitted strategy forwards eligible A and AAAA
queries concurrently. `preferipv4`/`preferipv6` still query both families and
only suppress the non-preferred answer when the preferred family has usable
records; `ipv4only`/`ipv6only` do not forward the ineligible family. Bootstrap
fallback runs once, only when every eligible family is unusable, and its result
is filtered by the same eligibility set.

Cache and singleflight keys include the ingress profile, routing policy, scope,
and operation. Requests that are not cacheable or coalescable bypass both
layers; cancellation releases their flight state. DNS persistence uses an
`HDNS` v2 record under the `dns:v2:` namespace. Writes are bounded and epoch
fenced: a flush discards older queued epochs before writing the newest state,
while stale, corrupt, version-mismatched, or policy-mismatched rows are
skipped on restore. A rollback to a pre-v2 binary therefore ignores v2 rows;
they may remain in `cache.db` and do not change the old runtime's behavior.

Runtime reloads publish a new coherent generation. Each DNS runtime pins the matching
outbound runtime, so existing leases keep the old node configuration and session pools
while new requests use the replacement even across the publication boundary. After old
leases and DNS transports retire, the old outbound pools stop accepting streams and
drain live TCP/UDP flows; process shutdown remains the force-close boundary. Retirement
closes stalled DNS generations at the deadline and caps retained generations. Pooled
transports single-flight initialization and close idle sessions exactly once.
Cache, flight, persistence, runtime, transport, projection, and outcome
diagnostics use independent monotonic atomic counters. An internal scrape
loads each counter without blocking request writers; it is best-effort rather
than one coherent instant, so cross-counter invariants must not be inferred.
Structured failure logs expose only bounded `error_kind` classes
(forwarder, persistence, projection, and transport) plus bounded fields such
as the transport label; they omit query names, upstream addresses, and
free-form error payloads. This adds no public DNS metrics endpoint,
configuration key, or API.

## 10. Clash API

Enabled when `experimental.clash_api.external_controller` is non-empty.

Core surface: `/version`, `/configs`, `/proxies`, delay endpoints, `/rules`, `/connections`, `/traffic`, `/stats`, `/logs`, `/dns/query`, cache flush, `/providers/proxies`, external UI auto-download (Yacd-meta). `GET /stats` includes a stable nested `udp` object; its complete schema is documented in the component reference.

Auth: `Authorization: Bearer` or `?token=` (percent-decoded).

## 11. Runtime privileges

- **root** required for real eBPF: load BPF, TC/cgroup/sk_lookup attach, netns, veth, transparent bind, sysctl.
- Docker: `--privileged --network=host --pid=host` and mount `/sys`.
- Tests use `MockEbpfBackend` / `--mock-ebpf` without privileges.

## 12. Security notes

- Treat config files and BPF objects as **privileged input**.
- Clash API has **no TLS**; bind to localhost or put a reverse proxy in front; set a strong `secret`.
- Bypass mark must stay on control-plane dial sockets or the gateway will loop its own traffic.

## 13. Authorship (design process)

- **eBPF datapath** (`honk-ebpf`, `honk-ebpf-common`, attach/maps path in `honk-core`): primary human design, implementation review, and verification focus of the project maintainer.
- **Remaining subsystems** (config parsers, outbound handlers, groups/health, DNS userspace, Clash API, much of the control-plane glue): largely authored with AI assistance; the maintainer performed **partial code review** rather than line-by-line ownership.
- See the root README for the same disclosure in project overview form.

## 14. Related docs

- [Configuration](./configuration.en.md)
- [Component reference](./components.en.md)
- [DNS canary and rollback runbook](./dns-rollout.en.md)
- [AGENTS.md](../AGENTS.md) — agent-oriented layout notes
