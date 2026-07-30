# AGENTS.md — honk

This file is written for AI coding agents that need to understand, build, test, and modify the project. It describes the actual layout and conventions observed in the repository (last verified against the tree on 2026-07-22).

## Project overview

`honk` is a Rust transparent-proxy engine for Linux, **inspired by** [dae](https://github.com/daeuniverse/dae) (eBPF datapath and configuration surface) and [sing-box](https://github.com/SagerNet/sing-box) (outbound groups, multi-protocol dialers, Clash-compatible API). It is not a line-for-line port of either: the kernel path follows dae's TC + match_set + `dae0`/`daens` model, the userspace outbound/control stack follows sing-box-oriented designs.

- An eBPF transparent proxy engine (`honk-core`) intercepts traffic with eBPF TC redirect (no global `iptables` TPROXY rules), classifies it in eBPF, and relays it through proxy handlers in userspace.
- Shared configuration types and parsers (`honk-config`) parse the original dae `{ section { ... } }` configuration syntax — the primary and only documented config format.
- Status: **experimental alpha** (`v0.0.1-alpha`). Expect breaking changes.
- License: **GPL-3.0-only**. Repository: <https://github.com/Glassyiris/honk>
- Documentation: `README.md` / `README_CN.md` (bilingual overview, feature checklist, TODO list) and `doc/` — `design.en.md`, `configuration.en.md`, `components.en.md`, `benchmark.en.md` (lab topology, how to run, honk-vs-dae results; plus `.zh.md` translations), all currently in sync with the code.

## Repository layout

```text
.
├── Cargo.toml / Cargo.lock   # Workspace manifest (release + release-musl profiles)
├── Justfile                  # Day-to-day dev tasks (build, test, run, debug via clash API, cleanup)
├── README.md / README_CN.md  # Bilingual project overview
├── AGENTS.md                 # This file
├── LICENSE                   # GPL-3.0-only
├── config.dae                # Full-featured example config (production-leaning)
├── config.min.dae            # Minimal example (good for --mock-ebpf dev)
├── example.dae               # Annotated example (Chinese comments)
├── doc/                      # design / configuration / components / benchmark docs (en + zh)
├── bench/                    # lab-bench.sh: unified honk-vs-dae A/B harness (runs on the engine host; README has usage + measurement traps)
├── ci/                       # zigcc/zigcxx: zig cc/c++ wrappers for cross builds (strip CMake's clang-style --target from boring-sys ASM rules + rustc's aarch64 errata linker args; used by build-musl and the release workflow); zig-bindgen-env: derive BINDGEN_EXTRA_CLANG_ARGS from `zig cc -E -v` for cross bindgen
├── .github/workflows/        # release.yml: tag-triggered test + cross-build + GitHub Release
└── crates/
    ├── honk-config           # Config schema + dae-syntax parser + share links (workspace member)
    ├── honk-ebpf-common      # no_std shared eBPF/userspace types (workspace member)
    ├── honk-outbound         # Proxy handlers, groups, health checks (workspace member)
    ├── honk-core             # eBPF proxy engine, library + `honk-core` binary (workspace member)
    ├── honk-tool             # `honk-tool` CLI toolbox: `sub` subscription/node probing (workspace member)
    └── honk-ebpf             # Kernel eBPF programs (EXCLUDED from workspace, own Cargo.lock)
```

Notable absences (referenced by older docs but **not in this tree**): `Makefile`, `scripts/`, `Dockerfile`, `docker-compose.yml`, `plan.md`, `run_tests.sh`, `test-honk.sh`, `log/`, and the vendored reference checkouts (`honk/`, `outbound/`, `sing-box/` — these paths are `.gitignore`d). Consequences:

- `just run` and `just deploy` call `scripts/debug-local.sh` / `scripts/deploy-gateway.sh`, which do not exist here — use `just run-debug` / `just run-dae` instead.
- `just docker*` and the README Docker section reference a missing `Dockerfile` / `docker-compose.yml`.
- There are no root-only netns/podman test scripts in the checkout; all runnable tests are unprivileged.

## Technology stack

- **Language:** Rust, edition 2024 (workspace-wide, including the eBPF crate).
- **Async runtime:** Tokio (`full`).
- **eBPF:** userspace [aya](https://github.com/aya-rs/aya) 0.14 (optional `ebpf` feature in `honk-core`); kernel side `aya-ebpf` 0.2 targeting `bpfel-unknown-none` (nightly + `-Zbuild-std=core` + `bpf-linker`).
- **HTTP API:** axum 0.8 (with `ws`) + tower-http 0.7 (optional `clash-api` feature of `honk-core`, on by default).
- **QUIC:** quinn 0.11 (TUIC/Juicity/Hysteria2 outbounds, DoQ/DoH3 DNS); `h3`/`h3-quinn` for DoH3 only — Hysteria2 ships its own minimal HTTP/3+QPACK layer.
- **TLS:** [boring](https://github.com/cloudflare/boring) 5.x (BoringSSL) + tokio-boring for TCP TLS and — via the custom `quinn_proto::crypto` backend in `honk-outbound/src/quic_boring.rs` — for QUIC handshakes; webpki-root-certs for CA roots. rustls remains only as a **dev/test** dependency (loopback servers proving wire interop). boring-sys builds BoringSSL from source: requires `cmake` + a C compiler + `libclang` (bindgen).
- **Persistence:** rusqlite 0.40 (`bundled`) for the `cachedb` SQLite cache.
- **Serialization:** serde, toml 1, serde_json, serde_yaml.
- **Logging:** tracing + tracing-subscriber (`env-filter`, `json`); also `log`.
- **HTTP client:** reqwest 0.13 (rustls, no default features) — subscriptions.
- **Error handling:** anyhow + thiserror 2.
- **Misc:** socket2, ipnet, aho-corasick, lru, dashmap, parking_lot, h2 0.4 (h2mux + DoH), tokio-tungstenite (WS transport), zip (external-UI download only), libsystemd (only `sd_notify`), nix (only `clock_gettime`), aes-gcm/chacha20poly1305/blake3/sha1/sha2/hmac/hkdf/md-5.
- **Dev/test:** tempfile, tokio-test, rcgen 0.14, tokio-tungstenite, criterion 0.5 (DNS benchmarks).

## Crate responsibilities

### `crates/honk-config`

Configuration schema and parsers used by the rest of the project. Deps are pure-Rust (serde, regex, url, base64, chrono, uuid).

- `src/config.rs` — top-level `Config` / `GlobalConfig` (~40 global fields), `from_file` / `to_file` / `validate`, JSON helpers, and `ensure_builtin_nodes()` (injects the built-in `direct` node, mapped to `DirectHandler` via `NodeProtocol::HTTP`, idempotent). **The crate never calls `ensure_builtin_nodes()` itself** — `honk-core` calls it at startup and SIGHUP reload (`honk-core/src/lib.rs`); other consumers must call it explicitly.
- Format loading: the dae syntax is primary; TOML/YAML/JSON serde loaders remain for compatibility (undocumented). `from_file` picks by extension — recognized `.json`/`.yaml`/`.toml` try that format then fall back only among TOML/YAML/JSON (dae is never tried); unknown/missing extensions use the file-aware dae loader (including `include`) then try TOML → YAML → JSON.
- `src/parser/` — the dae-syntax parser. **`parser/mod.rs` is the entire real parser** (line/section based, ~1600 lines): file-aware `include` expansion (quoted/bare paths, glob, nested entry-relative resolution, canonical directory boundary, duplicate/cycle rejection), all sections, group policies and aliases (`fixed(0)`/`select`→Selector, `min_moving_avg`/`min_avg10`/`min_last_delay`→URLTest, `roundrobin`→LoadBalance, `fallback`→Fallback), nested `filter: group('a','b')` (comma or pipe separated) routed into `Group.groups`, DNS `upstream`/`routing { request/response }`, `fixed_domain_ttl`, `subscription`, `experimental`, `resolve_group_filters`. `section_parser.rs` is only the `Section` struct.
- Group filter resolution: `resolve_group_filters` resolves only node filters (`name('exact')`, `name(keyword: 'pat')` — case-sensitive substring); the "include all nodes" fallback applies **only** when a group has neither node filters nor sub-groups.
- `src/node.rs` — `Node` (all per-protocol fields, incl. **ECH**: `ech_enabled` / `ech_config` / `ech_config_path`) **plus `Group` and `GroupPolicy`** (Selector/URLTest/LoadBalance/Fallback). `src/group.rs` is a 2-line re-export. `Group.groups: Vec<String>` holds nested sub-group tags; `Group.default`, `final_outbound` (dae `final:`), `tolerance` (default 50 ms), `idle_timeout`, `interrupt_connections`, `check_url` (per-group health check target, sing-box urltest `url`).
- `src/dns.rs` — much richer than a plain upstream list: `DnsConfig` (`upstream`, `routing`, `strategy`, `cache`, `fixed_domain_ttl`), `DnsUpstream` (name, address, `protocol: DnsProtocol`, `tls_server_name`, **`outbound: Option<String>`** — per-upstream dial-path proxy tag), and the dae-shaped DNS routing model (`DnsRequestRule`/`DnsResponseRule` with AND-ed `DnsCond`s — Qname/Qtype/Upstream/Ip, each negatable — first match wins; actions Reject/AsIs/Accept/Upstream(name); legacy `rules`/`fallback` with conversion). `types.rs::DnsProtocol` has 6 variants: Udp, Tcp, Tls (DoT), Https (DoH), H3 (DoH3), Quic (DoQ). Request/response routing types are populated only by the dae parser (deliberately outside the serde tree).
- `src/share_link.rs` — `Node::from_share_link`, the single share-link parser: SIP002 `ss://` (all base64 forms, plugin suffix), `ssr://` base64 blobs, `vmess://` base64-JSON (v2rayN schema), trojan/trojan-go ws/grpc query params, AnyTLS pool params, hysteria2 auth/obfs/bandwidth (`upmbps`/`downmbps`)/port-hopping (`mport`/`mhop`)/QUIC-window params and `pinSHA256=<hex>` cert pins, **ECH params** (`ech_config=<base64url ECHConfigList>`, `ech=1`), plus socks5/http(s)/vless/hysteria2/tuic/juicity. Node name = decoded `#fragment`, else `scheme-host` (never leaks credentials). Chain links (`a -> b`): only the first hop is parsed. Used by the dae parser and `honk-core` subscriptions.
- `src/routing.rs` — `RoutingRule` (condition + outbound + priority + **`must` flag** — Go dae semantics: match does not finalize, continues searching), `RoutingCondition` (14 matcher lists incl. dscp, ip_version, mac, process_name, geoip/geosite), `RoutingOutbound` (Simple/Complex), `RoutingConfig`.
- `src/experimental.rs` — `ExperimentalConfig` { `clash_api: ClashApiConfig` (`external_controller`, `external_ui`, `secret`, **`default_mode`**, default "Rule"), `cache_file: CacheFileConfig` (`enabled`, `path` default `cache.db`, `cache_id`, `store_fakeip`, `store_dns`) } — also parsed from the dae `experimental { ... }` section.
- `src/subscription.rs`, `src/types.rs` (`NodeProtocol` 12 variants, `DialMode` ip/domain/domain+/domain++, `SubscriptionType`, `DnsProtocol`, plus the shared `default_true`/`parse_duration_secs` helpers), `src/error.rs` (`ConfigError`).

### `crates/honk-ebpf-common`

`#![no_std]` crate with constants and `#[repr(C)]` structs shared between the eBPF program and userspace `honk-core` (`aya` is only a non-BPF-target dependency, for `Pod` impls). **Both sides must agree on layout and map key sizes** — changing a map type or constant means updating this crate, `honk-ebpf`, and the map writers in `honk-core` together.

- `src/lib.rs` — datapath constants (`TPROXY_MARK`, `DAE_BYPASS_MARK` = `0x100`, `MAX_OUTBOUND_STATS` sizes), `DaeParam`, `ParamKey`, `OutboundIndex` (`#[repr(u8)]`: Direct=0, Block=1, UserBase=2, MustRules=0xFC, ControlPlaneRouting=0xFD, LogicalOr=0xFE, LogicalAnd=0xFF), `ConnTuple`, `RoutingMeta` (u64 union, size pinned by compile-time asserts), `RedirectTuple`/`RedirectEntry` (records `outbound` for rx stats), `LpmKey`, `PidPname`, `OUTBOUND_STATS_*` constants + `outbound_stats_index()` (= `outbound * 4 + counter`), `OutboundStats`.
- `src/conn.rs` — `ConnState` (conntrack value), `ConntrackArgs`, `ParseTransportCtx`, `BpfStatsKey`, `TcpState`.
- `src/redirect_need.rs` — `TuplesKey`, `Tuples`, `RoutingResult`, `RoutingHandoffEntry`, `DomainRouting` (per-domain rule bitmap), `IPPort`, `PortRange`, `PIDName`, `MAX_MATCH_SET_LEN` (=128).
- `src/route.rs` — `MatchSet` (dae-core `match_set` layout), `MatchSetValue`, `MatchType` (incl. DNS match types `Upstream`/`QType`), and the routing-group pre-filter constants (`ROUTING_GROUP_*`, `routing_group_index()`, `ROUTING_META_MAP_LEN` = 17 — 1 rule-count slot + 4 group bitmaps × 4 words, asserted at compile time).
- `src/event.rs` — `DaeEvent` (72-byte ring-buffer event), `DaeEventType` (`Blocked` is defined but never emitted; only Udp/TcpConnOverflow are sent). `src/dae_ip.rs` — `In6Addr` union + v4-mapped helpers.
- Invariants: IPv4 flows are stored as `::ffff:<ipv4>` (network byte order) everywhere; all wire structs are `#[repr(C)]`. Note: `DnsCacheEntry` and `DomainKey` do **not** exist (domain routing uses `DomainRouting`; DNS caching is purely userspace). There are a few intentional duplicate definitions (`MAX_MATCH_SET_LEN`, `PortRange`, `TcpState`). No tests in this crate.

### `crates/honk-ebpf`

Separate Cargo project (**excluded from the workspace**, own `Cargo.lock`) building the kernel eBPF programs. Edition 2024, `aya-ebpf` 0.2, release profile `panic = "abort"`, `lto = true`, `opt-level = "z"`. `src/main.rs` is the `#![no_std] #![no_main]` bin (spin-loop panic handler + module declarations). Optional `log` feature enables `aya-log-ebpf`; without it `log_shim.rs` macros compile to no-ops.

- TC programs use raw `#[unsafe(no_mangle)] #[unsafe(link_section = "classifier")]` fns (not the `#[tc]` macro — avoids a verifier issue on kernel ≥ 7.0). Verdict convention: bodies return `action::Verdict` = `Result<c_long, c_long>` (`Ok` = normal verdict, `Err` = early exit), entry points flatten via `action::flatten`; the named `TC_ACT_*` consts live in `src/action.rs` — internal sentinel codes (e.g. `LOAD_REDIRECT_TUPLE_FALLBACK`, bpf_loop `LOOP_CONTINUE`/`LOOP_BREAK`) are NOT verdicts and stay separate. Socket helpers live in `src/sk.rs`: `sk_assign_by_index` (the TC-side counterpart of aya's `SockMap::redirect_sk_lookup`, which only accepts `SkLookupContext`) and `probe_tcp_socket`/`probe_udp_socket` (lookup + release probes used by the NAT-loopback check) — all release the lookup's implicit socket reference. Program inventory:
  - `lan_ingress_l2/l3` — LAN classify/route/redirect into `dae0`, tx stats, DNS port-53 fast path, `CLASSIFIED_MARK` dedup for bridge master+slave double-attach (`src/ingress.rs`).
  - `wan_ingress_l2/l3` — reverse-direction conntrack refresh (skipped single-homed).
  - `lan_egress_l2/l3`, `wan_egress_l2/l3` (`src/egress.rs`) — reverse conn state; locally-originated traffic routing (pname via `COOKIE_PID_MAP`, control-plane bypass, `OUTBOUND_CONNECTIVITY_MAP` aliveness, redirect to control plane).
  - `dae0_ingress` — reply path: rx stats from `RedirectEntry.outbound`, MAC rewrite, redirect to original LAN iface.
  - `dae0peer_ingress` — `bpf_sk_assign` of the TPROXY listener via `LISTEN_SOCKET_MAP` inside `daens`.
  - `tproxy_sk_lookup` (`src/sk_lookup.rs`) — assigns flows to transparent listeners (keys 0-3 = TCP4/UDP4/TCP6/UDP6).
  - cgroup sock_create/sock_release/connect4/6/sendmsg4/6 (`src/cgroup.rs`) — cookie → `PIDName{pid, pname}` for process-name rules + control-plane bypass.
- `src/route.rs` is the routing engine (`route()` + `RouteCtx` state machine over `MatchSet`s via `bpf_loop`, 1:1 port of Go dae's `kern/tproxy.c`, group-bitmap skip logic). `src/routing.rs` is only a small helper (`bpf_sock_is_dae_socket`) — don't confuse the two. `src/outbound.rs` is an empty file. (The old `tproxy_sockops`/`tproxy_sk_msg_redir` no-op stubs in `src/compat.rs` were removed — the sockops+sk_msg combo caused kernel panics on some kernels, TC redirect is used instead, and honk-core loads programs strictly by name so nothing referenced them.)
- Key maps (`src/maps.rs`): `CONN_STATE_MAP` (plain hash, 512K — no kernel eviction; userspace janitor sweeps with state-based timeouts), `REDIRECT_TRACK` (plain hash, 64K), `ROUTING_HANDOFF_MAP` (plain hash, 64K), `CONN_STATE_OCCUPANCY` (per-CPU insert/delete gauge for the janitor's pressure watermarks), `ROUTING_MAP` (array of 128 `MatchSet`s), `ROUTING_META_MAP` (17 slots: rule count = atomic commit switch + 4 group bitmaps), `DOMAIN_ROUTING_MAP` (plain hash, 64K), `DEST/SOURCE/MAC_LPM_ROUTING_MAP` (tries capped at 64K entries), `COOKIE_PID_MAP`, `OUTBOUND_CONNECTIVITY_MAP` (1536 slots: `outbound*6 + domain*2 + ipver`), `OUTBOUND_STATS` (per-CPU, 1024 slots), `LISTEN_SOCKET_MAP` (SockMap, 4), `EVENT_RINGBUF` (conntrack-overflow events only), plus per-CPU scratch maps.
- Per-outbound stats: index `outbound * 4 + counter` (tx_packets/tx_bytes/rx_packets/rx_bytes); tx counted at `lan_ingress` when the routing decision lands, rx at `dae0_ingress`.
- Build (needs nightly + `bpf-linker`):

  ```bash
  cd crates/honk-ebpf
  cargo +nightly build --release -Zbuild-std=core --target bpfel-unknown-none
  # → crates/honk-ebpf/target/bpfel-unknown-none/release/honk-ebpf
  ```

  **Caveat:** `.cargo/config.toml` hardcodes `-C linker=/root/.cargo/bin/bpf-linker-wrapper` — a machine-specific absolute path. On a new machine, install `bpf-linker` and either provide that wrapper or point `linker` at `bpf-linker` (the CI workflow does exactly this `sed`).

### `crates/honk-outbound`

Outbound dialing, groups, and health checking. Re-exported by `honk-core` as `honk_core::{proxy, group, outbound}`.

- `src/runtime.rs` — **per-node runtime ownership** (`OutboundRuntimeRegistry`, ControlPlane is the single owner): `Node.id` → `NodeRuntime` (immutable node config, `OutboundCapabilities`, `ProtocolRuntime`). Built/validated at startup and rebuilt on reload (nil/duplicate UUIDs abort), swapped two-phase, old registry `shutdown()`s its pools. `Node::default()` assigns a v4 UUID (the derive-Default nil UUID silently poisoned struct-literal construction incl. the built-in `direct` node).
- `src/proxy/mod.rs` — the `ProxyHandler` trait (`dial`, `dial_udp` [default: unsupported error], `test_connectivity`, pooling hooks `pool_ready_streams`/`pool_bare_tcp`, `set_runtime_registry`), `ProxyRegistry` (registers all 13 handlers; stateless — session ownership lives in the runtime registry, handed to handlers via `install_runtime_registry`), `ProxyStream` (`into_tcp_stream` downcast enables honk-core's zero-copy splice path — the `as_any` dispatch must go through `(*stream)`, regression-tested), `UdpProxySocket`.
- Handlers: `direct` (bypass-marked dial; UDP `relay_addr` **is the target**), `block`, `http` (**real HTTP CONNECT** for non-built-in HTTP nodes — the built-ins keep their marker handlers; `http.rs`), `socks5` (CONNECT + UDP ASSOCIATE — `relay_addr` is the server-assigned relay, **no loopback bridge**), `shadowsocks` (+ `shadowsocks_2022.rs` SIP022: BLAKE3 KDF, EIH, replay protection; selected via `is_2022_method`), `ssr` (TCP only; unsupported protocol/obfs plugins — auth_aes128_*, tls1.2_ticket_auth — are hard errors, never a silent origin/plain fallback), `trojan` (+ UDP associate bridge), `trojan_go` (own smux-style mux, TCP only — collision-checked u16 ids, 128 streams per mux, max 2 muxes/key, HOL-stall closes the mux, cancel-safe header guard; `trojan-go://` share links map here, not to plain trojan), `vmess` (TCP only), `vless` (TCP only), `anytls`, `tuic`, `juicity`, `hysteria2/`. Unknown `node.transport` values are rejected at config validation (no silent raw-TCP degradation); an unparseable `tls_pin_sha256` fails closed at connector build.
- **UDP support matrix** (verified): `dial_udp` works for direct, socks5, shadowsocks (+2022), trojan, hysteria2, anytls, tuic, juicity. **Not implemented for vmess, vless, ssr, trojan-go** (matches the README TODO).
- **UDP transport invariant:** tunnel handlers override `dial_udp_transport` to frame datagrams directly on the tunnel (no loopback bridge): trojan (`addr | u16 len | CRLF | payload` on the associate stream), anytls (sing UoT v2 — `open_uot_stream`: SYN + magic target PSH, `isConnect` byte + SOCKS5-form destination, then bare `u16 len + payload` written straight to the session writer; inbound v1/v2 framing parsed per PSH payload; demux delivery is a **drop-on-full 4096-deep queue** so a hot UDP flow can never backpressure the shared session), ss (encapsulated datagrams), tuic/hy2 (QUIC datagrams via the connection demux), juicity (length-framed bi stream). Only `direct` (target itself) and `socks5` (server-assigned relay) use a raw socket. The `UdpEndpointPool` reply-handler exit kills its endpoint; fast-path send failure does too (a dead transport must not black-hole a flow). A handler that skips the tunnel framing silently bypasses the proxy and makes UDP health probes measure the gateway's own egress.
- `src/session.rs` — **unified session pool v2** for multiplexed outbounds (h2mux, AnyTLS, Trojan-Go; QUIC protocols keep the single-connection `quic::QuicClient` holder): per-key pools with a hard session cap, least-loaded scheduling over `Active` sessions (`SessionState` Active/Draining/Closed), **pool-owned dial tasks** (first caller registers; cancelling a caller only ends its own wait; `DialSignal` broadcasts outcomes; `DialGuard` with inflight id as panic backstop), exponential dial-failure backoff, per-key janitor (min_idle prewarm + idle reaping + jittered max-age drain), pool metrics, idempotent shutdown (offers/inserts/prewarm rejected, waiters woken `PoolClosed`, sessions closed, tasks zero). Capacity is a per-session **semaphore permit** (`try_reserve` = Active→acquire→recheck; `open_with` does atomic reserve+open, retrying once on a fresh session for `OpenError::Session`, never for `Refused`). **`insert` always tracks, even over the cap** — an untracked session is orphaned from the janitor while its demux task holds the connection forever (beta.24 production incident: per-flow mux sessions leaked unboundedly on bare-TCP pool hits).
- `src/proxy/transport.rs` — shared stream-transport layer for trojan/vmess/vless (TCP → optional TLS → h2mux **or** WS/gRPC, driven by `node.mux`/`node.transport`/`ws_path`/`ws_host`/`grpc_service`); hand-rolled minimal gRPC-over-H2 client (interop-verified against an official sing-box trojan+grpc inbound — opening HEADERS carries no END_STREAM, `:scheme` is https over TLS).
- `src/proxy/mux.rs` — h2mux (`node.mux = true`; h2mux only, no smux/yamux): process-wide `SessionPool` (`src/session.rs`) caching HTTP/2 sessions per `host:port|tls|sni|pwhash|verify`, sing-mux session header `0x00 0x02`, one h2 stream per dial (`:method CONNECT`, `:authority localhost`, 200 OK expected), least-loaded session reused below 8 streams, one redial on GOAWAY/error, idle (0-stream) sessions closed after 60s by the per-session watcher. Mux and WS/gRPC transport are mutually exclusive (mux wins). honk writes the proxy handshake onto each h2 stream instead of sing-mux's outer-handshake + per-stream `StreamRequest` — the 4B interop gate against an official sing-box multiplex inbound **fails** ("stream closed because of a broken pipe"), so this is an **honk h2 carrier, NOT sing-mux compatible**: only usable with servers following the same convention (ignored interop test in `mux.rs::tests`).
- `src/proxy/anytls.rs` — sing-anytls session multiplexing. **Ownership**: each node's pool lives in `NodeRuntime::AnyTls` (runtime registry; handler resolves by `Node.id`, fallback pool without a registry); pool keys are the constant `POOL_KEY` — the old `host:port|pwhash|sni|verify` fingerprint only existed for the static pool. **Write path**: every frame goes through the single ordered writer task (`WriterQueue` — data rides bounded permits = backpressure, control keeps reserved headroom, the SYN+PSH opening pair is one atomic batch; abandoned mid-open registrations clean up with a FIN, not a session kill) which **gather-writes**: after the blocking pop it drains what's already queued (≤64 frames / ≤256 KiB, never waits) into one `write_all` + single `flush`, and data permits release only after the batch is written. **Read path**: demux dispatches by `sid`; a full TCP sink backpressures up to `HOL_STALL_TIMEOUT` (5s) before killing just that stream (reset to the reader after queued data); **UoT sinks drop-on-full**. Typed events: SYNACK-with-data = stream error (ConnectionReset), session failure = terminal error (ConnectionAborted after queued data). Streams hold a semaphore permit for life; sessions rotate via max-age (30 min × jitter) and `anytls_min_idle_session` / `anytls_idle_session_timeout` per node. UoT UDP uses the direct `open_uot_stream` path (see the invariant above), not the loopback bridge.
- `src/quic.rs` — shared quinn 0.11 plumbing for tuic/juicity/hysteria2: `client_config(node, alpn, QuicClientOptions)` (async — may run ECH discovery) assembling a quinn ClientConfig over the **BoringSSL crypto backend**; `QuicClientOptions` carries all transport tuning (congestion factory via `congestion_factory` for cubic/new_reno/bbr or `BrutalConfig` for hy2's fixed-rate sender, keep-alive, stream/conn receive windows, MTU-discovery switch) — protocol handlers map their own `Node` fields into it, the shared layer never reads protocol-specific fields. Also: client `Endpoint` on `SO_MARK`'ed UDP sockets, single-flight `QuicClient<C>` connection holder (rotation overlaps by construction: flows own their `(Connection, Arc<C>)` pair, so a re-dialed connection only takes new flows while in-flight ones finish on the old), `QuicBiStream`, plus `#[cfg(test)] testutil` in-process QUIC servers (rustls, for interop coverage). Client caches are **per handler instance** (`ClientCache`, keyed by server + blake3 credential fingerprint — never a process-global map, never a cleartext password in a key).
- `src/quic_boring.rs` — **quinn-proto `crypto::Session` over BoringSSL QUIC APIs**, with a process-wide TLS 1.3 ticket cache (`SESSION_TICKETS`, hostname-keyed, explicit `SSL_set_session` — BoringSSL has no implicit TLS 1.3 client cache; pinSHA256 nodes never resume so a PSK can't bypass the pin). Server-side probing (rtt_probe example): quic-go resumes fine, official tuic-server issues no tickets, no official server accepts 0-RTT early data (`SSL_set_quic_method` / `SSL_provide_quic_data` / `SSL_export_keying_material`): TLS 1.3 handshake, RFC 9001 key schedule (HKDF + AEAD + header protection via `boring::aead`, `aes`, `chacha20`), key update, retry integrity, transport-params plumbing. This is what makes **ECH on QUIC** (hy2/juicity/tuic/DoQ/DoH3) and a real Chrome QUIC ClientHello possible — rustls has no client ECH, quiche exposes no per-connection ECH hook. Header-protection masking is pn-length-aware (hard-learned: a fixed 4-byte mask corrupts short-pn payloads and self-cancels against a same-bug peer).
- `src/proxy/tuic.rs` (TUIC v5: TLS-exporter auth on uni stream, TCP = bi stream, UDP = datagrams with uni-stream fallback + fragmentation, 10s heartbeat; **receive windows default to 8 MiB stream / 32 MiB conn** (quinn's 1.25 MiB caps a stream at ~12.5MB/s per 100ms RTT, too small for long-fat links; `tuic_init_stream_recv_window`/`tuic_init_conn_recv_window` node fields override; hy2 `hy2_init_*` fields likewise — all three QUIC protocols share these defaults)), `src/proxy/juicity.rs` (ALPN `h3`, UDP on one length-framed bi stream, **BBR congestion by default** — upstream juicity/juicity-rs default; wire format verified interop against the juicity-rs server: TLS-exporter auth, `[network][trojanc metadata]` stream header, per-datagram `[metadata][len u16][payload]`), `src/proxy/hysteria2/` (`mod.rs` handler: ALPN `h3`; **brutal** fixed-rate sender when `hy2_up_mbps` is set ([`quic::BrutalConfig`] — window = rate×RTT, loss ignored), otherwise BBR; `hy2_down_mbps` is advertised via `Hysteria-CC-RX`; `h3.rs` self-contained minimal HTTP/3+QPACK for `POST https://hysteria/auth` status 233 — **must not advertise `SETTINGS_H3_DATAGRAM`** in the client preface: it makes the server's quic-go http3 layer race hysteria's UDP manager for datagrams and deterministically eats the first one; `salamander.rs` self-contained BLAKE2b-256 + XOR obfs socket, also carrying client-side **port hopping** (`hy2_port_hopping`/`hy2_hop_interval` — first send already hops; received packets have their source port rewritten to the nominal remote so DNAT'd hop ports look stable to QUIC). `tls_pin_sha256` (pinSHA256) replaces PKI/hostname checks in both `tls.rs` and the QUIC backend). One shared QUIC connection per node; per-session loopback UDP bridges.
- `src/tls.rs` — **BoringSSL TLS client**: webpki root store and no-verify variants, a **real Chrome fingerprint** toggled process-wide via `set_tls_mode` (`tls_implementation = "utls"`) — GREASE, permuted extensions, X25519MLKEM768+X25519 key shares (`mlkem` feature), Chrome sigalgs/curves, brotli cert compression, ALPS-h2, ECH GREASE — and **real ECH** per node (`ech_config` / `ech_config_path`, `SSL_set1_ech_config_list`; ECH rejection is fail-closed per RFC and surfaces retry configs in logs). `ech_enabled` without a static config triggers **DNS HTTPS-RR discovery** (`discover_ech_config`, RFC 9460 via the bootstrap resolver or first system nameserver, per-domain cache, fail-open) at connect time. `set_utls_imitate` accepts `chrome*` only (other values warn and fall back — Chrome is the only profile). `build_connector(node)` for proxy outbounds, `build_dns_connector()` for DoT/DoH upstreams.
- `src/bootstrap.rs` — **bootstrap DNS resolution for proxy-server hostnames** (dae `bootstrap_resolver` parity): process-wide resolver querying over bypass-marked UDP/TCP with a hand-rolled wire codec, falling back to the system resolver. Node dials must use it (wired into `util::connect_marked` and `quic.rs`), never bare `lookup_host` — otherwise resolution deadlocks against honk's own intercepted DNS path. Also carries the raw-query path behind ECH discovery: `query_ech_config` (HTTPS RR qtype 65, SVCB `ech` param parsing) used by `tls::discover_ech_config`.
- `src/util.rs` — `connect_marked` / `connect_outbound` (TCP with `SO_MARK`, keepalive, timeout), `udp_marked_bind`, `udp_loopback_bind`. `marked_udp_socket` also requests 8 MiB `SO_RCVBUF`/`SO_SNDBUF` (kernel clamps to 2×`rmem_max`; honk-core raises `net.core.rmem_max`/`wmem_max` to 16 MiB at startup) — the 208 KiB default caps QUIC at ~2 Gbps/ms RTT. **SO_MARK discipline:** every control-plane-originated socket must carry `DAE_BYPASS_MARK` (or be loopback) or `wan_egress` re-routes it into `daens`, looping the gateway's own traffic.
- `src/alive/` — `AliveDialerSet` health checking. Split: `mod.rs` (state, thresholds, registries, eBPF connectivity-push callback, `StickyCache`), `probe.rs` (`probe_node` HTTP/raw-connect, `probe_node_udp` DNS-through-`dial_udp`, concurrent cycle runner), `collection.rs` (`DialerCollection`: latencies + moving average + alive flag; failures append a synthetic 10s sample flagged `synthetic` — counts for selection but skipped by the display path), `latencies.rs` (O(1) ring buffer, cap 10; samples carry measurement `SystemTime` — clash history renders real times, and `last_real_sample()` filters synthetic entries so dashboards never show a bogus 10000ms).
  - Per-node state: 3 domains (`Tcp`, `DnsUdp`, `DataUdp`) × v4/v6. **Asymmetric thresholds** — probe: TCP=1, UDP=3; traffic-reported: TCP=10, DnsUdp=3, DataUDP=50. Exponential backoff 5s→300s (at 10 consecutive failures the node enters deep backoff but keeps probing on the 300s max-cooldown cadence — no permanent stop, sing-box-style unconditional re-testing), recovery after 2 consecutive successes, 60s registration grace period, URLTest idle-sleep registry (default 30 min), probe history (100/node/domain).
  - UDP probe (injected by honk-core via `set_udp_probe`): one minimal DNS query to the first `global.udp_check_dns` target (default 8.8.8.8:53) through the node's own `dial_udp`; success marks **both** UDP domains alive with the measured RTT, failure adds one probe failure per UDP domain. UDP probes never touch TCP state and vice versa. `has_udp_state(node)` distinguishes "never UDP-probed" from "UDP-probed and dead". Per-group custom check URLs are probed and tracked separately: `(member tag, check_url)` state (TCP-only, 1-failure death, same backoff/recovery) via `sync_group_check_urls` — a member dead for a group's own target is excluded from that group only. Members resolve dynamically each cycle through the group manager (`set_url_member_resolver` → `delay_test_members`): a sub-group member is probed through its current pick and the result recorded under the sub-group's TAG (sing-box RealTag semantics), so nested URLTest groups rank sub-groups as units.
- `src/group/` — `GroupManager` (`mod.rs`: core types + `SharedGroupManager = Arc<parking_lot::RwLock<Arc<GroupManager>>>`; `selection.rs`: all policy logic).
  - **Authoritative selection** (sing-box semantics): the dial path returns exactly the policy pick — manual Selector choice, current URLTest winner, rotated LoadBalance node, pinned Fallback node. The only multi-candidate race left is a cold URLTest group (no measurements yet). Never reintroduce parallel racing elsewhere.
  - **Nested groups:** `Group.groups` names sub-groups whose own policy pick contributes one candidate each; recursive flattening with depth cap `MAX_GROUP_DEPTH` = 8 + visited set; construction-time DFS cuts cycle-closing edges with a warning. Member identity is the tag: `node_names_in_group` (member tags), `leaf_node_names_in_group` (real nodes), `delay_test_members` (`(tag, leaf)` pairs), `selection_chain` (current picks down to the leaf).
  - URLTest keeps separate TCP/UDP selections (`SelectionNetwork`; with a group `check_url`, TCP liveness/ranking uses the per-(node, url) probe state — Selector groups ignore check_url with a warning; UDP ranks by DataUDP→DnsUDP→TCP latency and mirrors the TCP selection when no UDP data exists), tolerance hysteresis (`group.tolerance.max(1)` ms; baseline is the incumbent's **current** measured latency, sing-box `Select()` parity — not the stale at-selection value), re-evaluated lazily on the dial path / selection queries; a dial failure clears the node's latency history (sing-box `DeleteURLTestHistory` parity) so the next connection re-selects immediately; LoadBalance rotates per group via an independent `AtomicUsize` and never interrupts; Fallback pins the first alive member in declaration order until it dies (no failback on recovery). Selector-choice change callbacks (persisted by honk-core via `cachedb`), `interrupt_connections` on selection changes, URLTest idle sleep (`idle_timeout` stops health checks for idle groups). Config reload swaps in a rebuilt manager and migrates surviving selector choices (`migrate_selector_choices_from`).
  - **UDP candidate exclusion** (`filter_alive_candidates`): DataUDP or DnsUDP alive → selectable; **both** UDP domains explicitly dead → excluded even when TCP is alive (a TCP-only node must not attract UDP flows); never UDP-probed → inherits TCP liveness.
- `src/urltest.rs` — on-demand latency measurement backing the clash API delay endpoints: dials the check URL through the node's handler (real TLS handshake for https via `tls::build_http_probe_connector` offering `h2,http/1.1`; the probe dispatches on the negotiated ALPN — HTTP/1.1 HEAD or a real H2 session via the `h2` crate — so h2-preferring endpoints like gstatic work), status 200–499 OK; group measurement is concurrent (cap 10); **failures clear the node's latency history** so it sorts last. Empty URL normalizes to `https://www.gstatic.com/generate_204`.

### `crates/honk-core`

The proxy engine (library `honk_core` + `honk-core` binary). Cargo features:

- `default = ["clash-api"]`
- `ebpf` — real eBPF backend via aya (requires Linux kernel 5.8+); without it the engine runs on `MockEbpfBackend`.
- `clash-api` — Clash-compatible REST/WS API (pulls in optional axum/tower-http).

`build.rs` (only with `ebpf`) locates the eBPF object (`crates/honk-ebpf/target/bpfel-unknown-none/release/honk-ebpf` or `target/honk-core.o`), **verifies it contains `.BTF`** (rebuilds with `cargo +nightly` when missing or BTF-less — the rebuild strips `RUSTFLAGS`/`CARGO_ENCODED_RUSTFLAGS` from the child env because an environment RUSTFLAGS overrides `crates/honk-ebpf/.cargo/config.toml`'s `--btf` flags and silently produces BTF-less objects), copies it to `OUT_DIR/honk-ebpf.o`, and sets `HONK_EBPF_OBJECT`; `lib.rs` embeds it with `include_bytes!`. Runtime override: `--bpf-object`.

Module map:

- `src/lib.rs` — engine entry `run()`, `Cli`/`ClashCommand` (clap), **singleton instance lock** (`/run/honk-core.lock` flock: a second instance waits up to 240s for the previous one to exit — the datapath uses fixed names and a late shutdown cleanup would otherwise rip a fresh instance's dae0/daens/TC hooks out from under it), dae0 veth + `daens` netns setup (`169.254.0.1`/`.11`, `fd00:686f:6e6b::/64`; policy routing fwmark → table 100), scoped `with_daens_netns` setns helper, bootstrap-resolver install, subscription startup fetch (5s deadline) + merge tasks, sysctl helpers, `sd_notify`. `src/main.rs` is a thin binary.
- `src/control/` — the control plane:
  - `mod.rs` — `ControlPlane`: TPROXY TCP/UDP v4+v6 accept loop, `ControlCommand` mpsc channel (live commands: `ReloadConfig`, `MergeSubscription`, `GetStats`, `Shutdown`), 1024-connection semaphore (`try_acquire` — drop at capacity, never hold the fd), listener-fd publication to `LISTEN_SOCKET_MAP`.
  - `connection.rs` — per-flow handling: `serve_connection` (orig-dst → DNS interception → handoff → sniff → route → mode override → candidates → parallel happy-eyeballs dial → relay → **conn-state retire** (event-driven: both directions' entries removed at relay end; timeouts are the backstop) → pool deposit), `serve_udp_connection` (QUIC sniff → endpoint reuse → route → sequential dial → reply handler; endpoint reaping also retires conn-state via the pool's removal sink), 3-tier pooled dial (ready → bare → fresh; `HONK_POOL_DISABLE=1` bypass; multiplexed protocols — AnyTLS, Trojan-Go, mux=true nodes — opt out of the bare tier via `pool_bare_tcp`: their SessionPool already holds warm sessions, and a bare hit forces a new mux session per flow). `build_tuples_key` must stay `mem::zeroed()` — the kernel hashes all 40 key bytes including padding.
  - `sockets.rs` — TPROXY listener binds (daens-scoped), `new_udp_reply_socket` (**anyfrom** transparent socket bound to the flow's original destination), cached per-family DNS reply sockets (:53, `IP_PKTINFO` per-send source), `get_original_dst` (`SO_ORIGINAL_DST`/`IP6T`, `recvmsg` cmsg for UDP), `udp_fast_path`, `DnsBpfNotifier`.
  - `dns_control.rs` — `DnsController`: port-53 interception, singleflight dedup, 256-query semaphore with SERVFAIL degradation, `DOMAIN_ROUTING_MAP` pushes from resolved answers, learned-route persistence + rebuild after reload.
  - `reload.rs` — `apply_runtime_config`: the **single** rebuild pipeline for SIGHUP reload and subscription merge (router swap → config swap → outbound id map → GroupManager rebuild with choice migration → DNS forwarder recreate → eBPF push → domain-route rebuild), `config_with_subscription_nodes`, `resolve_outbound_nodes` (V6→V4 fallback, `final` fallback).
  - `routing_matcher.rs` — eBPF routing push: **two-phase commit** — compile (no map writes), publish (MatchSets → LPM plan → `set_routing_meta` last as the atomic switch), post-switch cleanup (tail clear + LPM prune). Never call `clear_routes` on the push path. Port-only generic proxy rules punt to `ControlPlaneRouting` in domain dial modes.
  - `quic.rs` — QUIC v1/v2 Initial decryption (RFC 9001/9369: HKDF initial secrets, AES-128-ECB header-protection removal, AES-128-GCM, CRYPTO reassembly 64 KiB cap); `packet_sniffer.rs` — per-flow QUIC sniff sessions with negative caches; `tcp_sniff.rs` — TCP sniff negative cache (3 failures → skip 600s).
  - `udp_endpoint.rs` — `UdpEndpointPool` (NAT 30s, reply idle 120s, per-endpoint routing cache + anyfrom reply socket cache; endpoints bound to a node are reaped immediately when it dies, not left to the timeouts).
  - `probers.rs` — `ProxyHttpProber` (HTTP through the node, 200–499 healthy), `ProxyUdpProber` (one DNS query through `dial_udp`).
  - `janitor.rs` — `BpfJanitor` (2s tick; sweeps CONN_STATE_MAP with state-based timeouts [TCP closing 10s / TCP active 120s / UDP 120s], REDIRECT_TRACK/COOKIE_PID/ROUTING_HANDOFF; pressure mode is watermark-driven via the `CONN_STATE_OCCUPANCY` gauge — 70% elevated sweep interval, 85% sweep every tick — with kernel overflow counters as the fail-closed last resort).
  - `drain.rs` — `DrainTracker` (reject-new + 5s drain during reload).
- `src/dns/` — userspace DNS: `forwarder.rs` (parse → strategy filter → request routing → cache → upstream → response routing loop (re-query depth ≤ 3) → fixed/optimistic TTL → cache → prefer-mode suppression → `DomainResolveNotifier`; serve-stale (RFC 8767: stale answers on upstream failure/SERVFAIL), stale-while-revalidate background refresh at <10% TTL, RFC 2308 SOA negative TTL; strategy: `*_only` answers the other family NODATA at request time, prefer modes forward both families and suppress the non-preferred response when the preferred family has answers for the name, checked via sibling cache entry or an extra sibling query), `routing.rs` (dae-shaped request/response rules: qname/qtype/upstream/answer-IP, negation, `fixed_domain_ttl`), `upstream_pool.rs` (transports pooled **per leaf node name**; `resolve_dial_leaf` = explicit `-> tag` via `SharedGroupManager` authoritative selection or implicit dae-style route of the DNS server IP through the traffic `Router`; UDP+proxy ⇒ TCP-DNS over the proxy; DoQ/DoH3+proxy ⇒ hard error; direct UDP uses a `DAE_BYPASS_MARK` socket per query with hedged retry (timeout/3 first attempt), txid matching, and TC→TCP upgrade), `transport/` (**encrypted upstreams**: `dot.rs` idle pool of 4 TLS streams, `doh.rs` one long-lived H2 session, `doq.rs` one QUIC conn ALPN `doq`, `doh3.rs` QUIC + `h3`-crate session, `tcp_pool.rs`, `framing.rs` RFC 7766 length-prefix; all retry once after session invalidation), `endpoint.rs` (upstream address parsing + bootstrap resolution), `cache.rs` (LRU + TTL + negative cache + 1h serve-stale retention), `wire.rs` (shared wire-format helpers), `persist.rs` (`store_dns`: 500ms batch writer → cache.db + startup restore; best-effort, drops never stall DNS), `mod.rs` (`DnsResolver` app-level A/AAAA resolution).
- `src/ebpf/` — `EbpfBackend` trait (`mod.rs`; `set_routing_meta` contract: group-bitmap slots first, rule-count slot 0 **last**), `mock.rs` (full in-memory `MockEbpfBackend` used by all tests), `real/` (gated by `ebpf`: `attach.rs` program load/attach incl. bond/bridge slaves + dae0/dae0peer/sk_lookup, `syscall.rs` raw `bpf()` map ops avoiding aya `Pod` bounds, `events.rs` EVENT_RINGBUF drain → tracing, `mod.rs` link holders + per-CPU stat readers), `maps.rs` (LPM key helpers, v4 → v6-mapped with prefix +96), `probe.rs` (`bpf()` batch-capability latch).
- `src/relay/` — `splice.rs`: `relay_splice` zero-copy bidirectional `splice(2)` with half-close propagation when both ends are plain `TcpStream`s; the first splice per direction is a capability probe (EINVAL/ENOSYS/EXDEV before any byte moved ⇒ lossless copy fallback + process-wide latch). **Never reintroduce a unidirectional splice path** (caused timeouts). `relay_auto` for TLS/protocol-wrapped streams (`copy_bidirectional`). UDP goes through `UdpEndpointPool`.
- `src/routing/` — userspace `Router` (priority-ordered compiled routes, `route_with_must`, `GeositeMatcher` hash sets + Aho-Corasick + regex), `lpm.rs` (`BinaryLpmTrie`), `geo.rs` (`GeoAssets`: `geoip.dat`/`geosite.dat` parsed once per Router build, only referenced codes decoded).
- `src/sniffing.rs` — **TCP only**: TLS SNI + HTTP Host (≤4096 bytes; buffered bytes returned for forwarding); `parse_client_hello_body` shared with the QUIC sniffer in `control/quic.rs`.
- `src/stats.rs` (`StatsManager` per-outbound conns/bytes/errors), `src/pool.rs` (`ConnectionPool`: bare pre-handshake TCP 60s idle, ready dialed `ProxyStream` 30s idle, 8/key, 300s max age; budgets — 2048 global FD cap, 64 ready targets/node, hot-target gating (2 flows/60s) for speculative ready deposits, multiplexed handlers excluded at the deposit site; hit/miss/entry metrics on clash `/stats`; all entries of a node purged the moment it flips alive→dead via the alive-set death callback), `src/connection_tracker.rs` (feeds `/connections`; entries carry the matched rule as clash-style rule/rulePayload (the rule's own type and payload — `DomainSuffix`/`GeoSite`/`DstPort`/`GeoIP`..., `Match` = fallback) and the selection chain leaf-first), `src/mode.rs` (`ModeState` Rule/Global/Direct + GLOBAL selection; `override_outbound` never overrides block/must), `src/cachedb.rs` (rusqlite WAL: selector choices, clash mode, `dns:` answers with lazy expiry, `delay:` last-real-latency samples per node (60s snapshot writer, restored at startup with 24h age-out — sing-box URLTest history storage parity), `cache_id` namespacing, corruption auto-reset to `*.corrupt-<ts>`), `src/subscription.rs` (fetch via reqwest: base64/simple, raw-line fallback, Clash YAML; share links via `Node::from_share_link`; startup races a 5s deadline; periodic refresh per `Subscription.update_interval` default 86400s, 0 = manual; merges through `ControlCommand::MergeSubscription`; **nodes live in memory only, never written back to the config file**; SIGHUP carries them over and triggers an immediate refresh).
- `src/clash_api.rs` + `clash_api/{logs,doh,ui}.rs` — Clash-compatible REST/WS API, started when `experimental.clash_api.external_controller` is non-empty. Auth: `Authorization: Bearer` or `?token=` (percent-decoded). Endpoints: `GET /`, `GET /version`, `GET/PUT/PATCH /configs`, `GET /proxies`, `GET/PUT /proxies/{name}`, `GET /proxies/{name}/delay`, `GET /group/{name}/delay` (on-demand via `honk-outbound::urltest`), `GET /rules`, `GET/DELETE /connections` (+WS `?interval=`), `DELETE /connections/{id}`, `GET /traffic` (WS or chunked JSON lines), `GET /stats` (userspace StatsManager snapshot, not eBPF `OUTBOUND_STATS`), `GET /logs` (WS or chunked, `?level=`), `GET /dns/query` (DoH-style JSON via the control-plane forwarder), `POST /cache/fakeip/flush`, `POST /cache/dns/flush`, `GET /providers/proxies`, `GET /providers/rules` (stub), `/ui` static hosting + background zashboard zip auto-download into an empty/missing `external_ui` dir (`HONK_UI_DOWNLOAD_URL` override; failures only warn). `logs.rs` is the tracing broadcast layer. Note: the API mutates `SharedGroupManager`/`ModeState` directly; `ControlCommand::{SetMode, SetSelectorChoice, TestNodeDelay, UpdateNode, RemoveNode}` exist but have no senders.

CLI (`honk-core` binary):

- Flags: `--config/-c` (default `/etc/honk/config.dae`), `--bpf-object/-b`, `--bpf-pin-root` (default `/sys/fs/bpf`), `--debug/-d`, `--mock-ebpf`. Log-level order: `--debug` → `RUST_LOG` → `global.log_level` → `info`.
- Subcommands (clash-style, **local only — none talks to a running engine**): `mode <rule|global|direct>` (rewrites `global.dial_mode` in the config file), `proxy <group> <node>` (validates existence and prints; persists nothing), `delay <node> [--url HOST:PORT]` (raw TCP connect timing, not a proxied urltest).

Benchmarks: `benches/dns.rs` (criterion, `harness = false`) — DNS endpoint parse, cache get/put + 90/10 mix, per-query routing match, framing, forwarder cache-hit, TcpPool/UpstreamPool exchange (mock servers must set nodelay or TCP exchanges measure Nagle, not the code). Run: `cargo bench -p honk-core --bench dns` (no external network needed).

### `crates/honk-tool`

The `honk-tool` CLI toolbox (bin crate, diagnostics that don't belong in the engine binary). Deps are honk-config + honk-outbound + honk-core (`default-features = false`, so no axum/aya). Subcommands:

- `sub <url|file> [--target HOST:PORT] [--url TEST_URL] [--timeout SECS] [--concurrency N] [--limit N] [--ua UA]` — fetch a subscription (or read a local share-link file), print per-protocol counts, then probe every node concurrently: server IP families, proxied connectivity to the test host over **both** IPv4 and IPv6 (a full protocol dial through the node via `ProxyRegistry`), and a proxied latency measurement (`urltest_node`). UDP liveness is probed too (minimal DNS A query + a real QUIC handshake via `quic::quic_handshake_probe`). Ends with alive-per-family counts and median latency.
- `bpf show <conn-state|redirect-track|domain-routing|routing-handoff> [--ip IP] [--limit N]` and `bpf stats` — quick reads of the running engine's pinned maps under `/sys/fs/bpf` (raw `bpf(2)`; no aya, no program load). `stats` prints overflow counters, the `CONN_STATE_OCCUPANCY` gauge, and non-zero per-outbound tx/rx counters.
- `diagnose [--api URL] [--pin-root PATH]` — one-shot read-only health check: engine process, `daens`/`dae0` presence, daens fwmark rule, pinned maps present, occupancy/overflow, clash API reachability. Exit summary `all checks passed` / `N issue(s) found`.
- honk-tool is a **static musl binary** for gateway deployment: build with the `build-musl` zig env (`ZIGCC_TARGET=x86_64-linux-musl` + ci wrappers) and scp — a gnu build fails to exec on VyOS.

## Runtime architecture (data path)

1. The eBPF LAN ingress program classifies each new TCP SYN / UDP datagram, marks proxy-bound flows with `tproxy_mark` (default `0x08000000`), and tc-redirects them into the `dae0` veth. Inside the `daens` netns, policy routing (fwmark → table 100) plus the `sk_lookup` program and the `dae0peer` TC ingress program (`bpf_sk_assign`) deliver them to the transparent (`IP_TRANSPARENT`) listener sockets bound in `daens`, preserving the original destination. Like Go dae, **no global `iptables` TPROXY/PREROUTING rules are installed**. DNS to port 53 takes a fast path that skips the full route loop.
2. `honk-core` accepts and reads the original destination (`SO_ORIGINAL_DST` / `IP6T_SO_ORIGINAL_DST` for TCP with transparent-`local_addr` fallback; `IP_RECVORIGDSTADDR` cmsg for UDP).
3. It takes the eBPF routing handoff entry (`routing_handoff_take`); if absent or `ControlPlaneRouting`, it falls back to the userspace `Router::route_with_must`. eBPF-decided `direct` with a nonzero mark is offloaded without userspace relay.
4. It sniffs TLS SNI / HTTP Host (TCP) or decrypts QUIC Initial SNI (UDP) for domain-based rules (skipped for must-rules, `dial_mode: ip`, or negative-cache hits; `dial_mode: domain` runs a DNS reality check).
5. Clash mode override → group/leaf selection (`SharedGroupManager` authoritative pick) → dial through the `ProxyHandler` (pooled: ready → bare → fresh; TCP dials race in parallel, UDP sequential) → relay: `splice(2)` when both ends are plain TCP, else `copy_bidirectional`; sniffed bytes are flushed to the proxy first.
6. DNS: port-53 flows are intercepted by `DnsController` → singleflight → `DnsForwarder` (request routing → cache → upstream pool: UDP/TCP/DoT/DoH/DoQ/DoH3, optionally through a proxy leaf → response routing) → answers are pushed into `DOMAIN_ROUTING_MAP` so eBPF can route subsequent connections to those IPs.

Key runtime invariants (do not break):

- **Bypass mark:** all control-plane-originated sockets (dials, probes, DNS upstreams, QUIC endpoints) carry `DAE_BYPASS_MARK` (`0x100`) or are loopback — otherwise the gateway loops its own traffic back into `daens`.
- **Anyfrom UDP replies:** proxied-UDP and DNS replies are sent from a transparent socket bound to the flow's original destination (created inside `daens`, cached per endpoint). Replying from the TPROXY listener dies in the host `dae0` path with source `169.254.0.11:<tproxy_port>`.
- **Netns discipline:** the process never leaves the host netns; `daens` is entered only through scoped, fully synchronous `with_daens_netns` switches (never `.await` inside — setns is per-thread; the original netns is restored on all exit paths, serialized by a process-wide mutex).
- **must/block are final:** clash mode override never overrides `block` results or dae `(must)` results.
- **Fail-closed on dead outbounds:** when health checking marks an outbound dead, `lan_ingress` drops new flows routed to it (`TC_ACT_SHOT`) — a dead single-node fallback takes proxied traffic down by design. Port 53 (TCP+UDP) is always exempt (dae parity). At startup/reload honk-core auto-injects `dip(<every lan/wan iface address>) -> direct(must)` (`Config::ensure_local_direct_rules`) so the gateway's own admin/SSH/API addresses never depend on node health.
- **eBPF connectivity pushes are group-OR:** the per-group alive slot is shared by all members — health callbacks write the OR of leaf-member states, never a single node's state (one dead member would otherwise `TC_ACT_SHOT` the whole group).
- **Internal traffic is never proxied:** `169.254.0.0/16` and `fd00:686f:6e6b::/64` (honk's own veth). **Broadcast/multicast is passed through at the eBPF layer**: `dst_is_special()` (crates/honk-ebpf/src/transport.rs) early-exits L2 broadcast/multicast MAC, 255.255.255.255, 224.0.0.0/4, 0.0.0.0 and ff00::/8 in lan_ingress/lan_egress/wan_egress — DHCP/mDNS/SSDP never enter routing or conntrack (breaks LAN DHCP on OpenWrt otherwise). The NAT-loopback local-socket probe in lan_ingress is unconditional (Go dae parity), so local services like dnsmasq are always detected.
- Reserved outbound indices: `0 Direct | 1 Block | 2+ user groups | 0xFC MustRules | 0xFD ControlPlaneRouting | 0xFE OR | 0xFF AND`.

## Build and test commands

### Rust workspace

```bash
cargo check
cargo build --release                 # whole workspace (needs cmake + C compiler + libclang for boring-sys)
cargo build --release -p honk-core    # engine (default features: clash-api, mock eBPF)
cargo test --all                      # full suite (see current status below!)
```

### honk-core with real eBPF

```bash
# Requires Linux kernel 5.8+, clang/llvm/libbpf headers, nightly + bpf-linker.
# build.rs auto-builds the eBPF object on first build (~30s).
cargo build --release -p honk-core --features ebpf
sudo ./target/release/honk-core --config /etc/honk/config.dae          # embedded object
sudo ./target/release/honk-core --config c.dae --bpf-object /path.o    # external object
```

Dev without kernel eBPF (unprivileged):

```bash
cargo run --release -p honk-core -- --config config.min.dae --mock-ebpf
```

### eBPF program standalone

```bash
cd crates/honk-ebpf
cargo +nightly build --release -Zbuild-std=core --target bpfel-unknown-none
```

### Justfile (preferred for day-to-day dev)

| Recipe | Purpose |
| -------- | --------- |
| `build` / `check` / `lint` / `fmt` | `cargo build --release` / `check` / `clippy --all -D warnings` / `fmt --all` |
| `test` / `test-ci` / `test-core` / `test-config` / `test-ebpf` | Test suites (`test` = full incl. known failures; `test-ci` = CI gate with the 3 known failures skipped; `test-ebpf` = honk-ebpf-common only) |
| `outbound-ci` / `outbound-ci-e2e` | honk-outbound gate (`ci/outbound-ci.sh`: fmt + clippy + honk-config & honk-outbound suites; `...-e2e` adds live hy2 e2e via `HONK_HY2_SERVER=`) — run after every outbound change |
| `dns-ci` | DNS subsystem gate (`ci/dns-ci.sh`: fmt + clippy + honk-config + honk-core dns/control + honk-outbound suites) — run after every DNS-path change |
| `outbound-ci` / `outbound-ci-e2e` | honk-outbound gate (`ci/outbound-ci.sh`: fmt + clippy + honk-config & honk-outbound suites; `...-e2e` adds live hy2 e2e via `HONK_HY2_SERVER=`) — run after every outbound change |
| `build-core` / `build-core-ebpf` | honk-core with `ebpf` feature |
| `build-musl` | Static musl build (`x86_64-unknown-linux-musl`, for VyOS/Debian) via the `ci/zigcc`/`ci/zigcxx` zig wrappers + `link-self-contained=no` (needs zig 0.14+) |
| `build-ebpf` | eBPF object standalone (nightly, `bpfel-unknown-none`) — warns when `RUSTFLAGS` is set (it overrides the crate's `--btf` rustflags) and verifies the object actually has `.BTF` (aya refuses BTF-less objects) |
| `run-debug` | Build with ebpf, clean previous state, run with `config.dae` + external object |
| `run-dae` | Run with `config.dae` + `--mock-ebpf` |
| `debug-status` / `debug-config` / `debug-alive` / `debug-stats` / `watch-debug` | Query the clash HTTP API on :9090 (`/version`, `/configs`, `/proxies`, `/group/{n}/delay`, `/stats`, `/connections`) |
| `bpf-progs` / `bpf-maps` | Inspect loaded BPF programs and pinned maps |
| `deploy-vyos HOST=...` | musl build + scp to a VyOS router |
| `clean` / `clean-all` | `cargo clean` / kill honk-core, remove `dae0`/`daens`, BPF pins, policy routes (live table 100 + legacy table 2023/iptables leftovers) |
| `cycle` | `clean-all` + `build-core` |
| `watch-core` | `cargo watch` rebuild |

The old `run` / `deploy` / `docker*` recipes were removed: they called `scripts/debug-local.sh` / `scripts/deploy-gateway.sh` / `Dockerfile` / `docker-compose.yml`, none of which exist in this tree.

### CI / releases

`.github/workflows/release.yml` runs on `v*` tags: a test gate (`cargo test --workspace --no-fail-fast` with the 3 known-failing pre-existing tests `--skip`ped — boring-sys needs `cmake` + `libclang-dev` installed), then builds `honk-core --features ebpf` for `x86_64`/`aarch64` × `gnu`/`musl` (native gnu via `cargo build`; the other three via **zig cc/c++ wrapper scripts `ci/zigcc` / `ci/zigcxx`** — under cross, CMake injects clang-style `--target` flags into boring-sys' ASM rules that real GCC rejects and zig rejects in Rust-triple spelling, so the wrappers strip them and re-anchor on `$ZIGCC_TARGET`; musl targets also set `link-self-contained=no` so zig supplies the CRT). The eBPF object is built once on the host with nightly + `bpf-linker` (the workflow substitutes the hardcoded linker path) and **verified to contain `.BTF`** before packaging. Tarballs go to a GitHub Release (prerelease when the tag contains `alpha`/`beta`/`rc`).

## Current test status (verified 2026-07-22, after the boring-tls migration)

Only pre-existing failures remain. `cargo clippy --all --all-targets -- -D warnings` is clean.

| Crate | Result |
| ------- | -------- |
| `honk-config` | lib 37 pass; `tests/example_configs.rs` 3 pass; `tests/share_link.rs` 26 pass / **2 fail** — `test_config_toml_round_trip` and `test_to_file_and_from_file_by_extension`: TOML round-trip serialization is broken (recent DNS config surface doesn't survive `toml`) — pre-existing |
| `honk-ebpf-common` | no tests |
| `honk-outbound` | lib 238 pass (the target previously did not compile at all). Includes: `tls::tests` (boring↔boring handshakes, real ECH round-trip, fail-closed ECH rejection, DNS HTTPS-RR discovery cache + discovery-driven ECH end-to-end, probe connector ALPN negotiation both ways), `urltest::tests` (h2-only server HEAD exchange), `alive::latencies` (synthetic-sample filtering), `bootstrap::tests` (SVCB ech parsing, stub-DNS ech lookup), `quic_boring::tests` (RFC 9001 A.1/A.2 vectors, boring↔rustls cross-impl keys, boring QUIC client ↔ rustls server interop in standard/Chrome-fingerprint/ECH-GREASE modes, fail-closed real ECH over QUIC), and the full hysteria2/tuic/juicity loopback end-to-end suites over the BoringSSL QUIC backend |
| `honk-core` | lib 351 pass (1 ignored); `tests/integration_test.rs` 21 pass; `tests/clash_api_test.rs` 31 pass; `tests/config_dae_routing_test.rs` **1 fail** — `test_routing_with_config_dae` expects `domain(suffix: jogiyw.sbs) -> direct` in the root `config.dae`, which no longer contains that rule — pre-existing |

Environment notes: (1) `routing::tests::test_geosite_*` need geo assets (`/etc/dae/geosite.dat` + `geoip.dat` — the CI test job downloads them); (2) tests must run with `HTTP_PROXY`/`HTTPS_PROXY` **unset** — reqwest picks up proxy env vars and the clash-ui download test's loopback fetch otherwise dies (`Connection reset`); (3) building `boring-sys` needs `cmake`, a C compiler, and `libclang` for bindgen (on nix set `LIBCLANG_PATH` + `BINDGEN_EXTRA_CLANG_ARGS`, e.g. via `~/.cargo/config.toml` `[env]`); (4) the release workflow's test gate `--skip`s the three pre-existing failures above; cross builds use the `ci/zig*` wrappers, not cross containers.

When fixing code, run at least `cargo test -p <crate>` for the crates you touched and don't regress the passing suites.

## Code style guidelines

- Rust source files do **not** carry SPDX/copyright headers; licensing and attribution live in the root `README.md`/`LICENSE`.
- Keep comments minimal: module-level `//!` docs (purpose + non-obvious architecture), `///` docs on public items, and "why" comments (rationale, invariants, wire formats, upstream parity notes, past-bug warnings). No section banners, no comments that restate the code. **After finishing any work phase, sweep the touched code for comments that describe the old behavior and delete or rewrite them** — stale comments are treated as defects, reviewed before the phase closes.
- Prefer `anyhow::Result` for application/binary code and `thiserror` for library error types.
- Use `tracing` macros for logging; prefer structured fields (`info!(network = "tcp", outbound = %name, ...)`).
- Use `tokio` async/await and `tokio::select!` for long-lived loops.
- Structs crossing the kernel/userspace boundary live in `honk-ebpf-common`, must be `#[repr(C)]` with stable layouts, and must be changed together with `honk-ebpf` and the `honk-core` map writers.
- Follow `cargo fmt --all` and keep `cargo clippy --all -- -D warnings` clean.
- Match the surrounding file's idioms; make minimal, scoped changes (no opportunistic cleanups).
- Documentation language: code comments and `.en.md` docs are English; user docs are bilingual en/zh (`README_CN.md`, `doc/*.zh.md`) — update both when you change documented behavior.

## Testing instructions

- `cargo test --all` runs unit + integration tests for workspace members. Everything runs unprivileged: `honk-core` tests use `MockEbpfBackend` and loopback sockets — no root, no kernel eBPF.
- Test locations:
  - `crates/honk-config/src/parser/tests.rs` — dae-syntax parser unit tests (sections, groups, nested filters, DNS upstreams/routing, subscriptions, experimental).
  - `crates/honk-config/tests/example_configs.rs` — keeps `config.dae`, `config.min.dae`, `example.dae` parseable.
  - `crates/honk-config/tests/include.rs` — file-based dae include loading (glob order, nested paths, merge semantics, cycles, and directory boundaries).
  - `crates/honk-config/tests/share_link.rs` — share-link parsing + config format round-trips.
  - `crates/honk-outbound/src/group/tests.rs`, `group/udp_selection_repro_tests.rs` — selection semantics (selector/urltest/LB/fallback, nested groups, UDP exclusion).
  - `crates/honk-outbound/src/alive/tests.rs` — health-check state machine, probe semantics, idle suspension.
  - `crates/honk-outbound/src/proxy/hysteria2/tests.rs` + inline `#[cfg(test)]` modules across `proxy/*`, `urltest.rs`, `bootstrap.rs` — wire-codec vectors and loopback end-to-end handshake/UDP-bridge tests (in-process QUIC servers via `quic::testutil`).
  - `crates/honk-core/tests/integration_test.rs` — config loading, routing, mock-eBPF workflow, SOCKS5/direct/block, TCP relay + splice, DNS resolver, stats, reload/subscription-merge pipeline.
  - `crates/honk-core/tests/clash_api_test.rs` — Clash API endpoints (auth, proxies, delay, connections, traffic/logs chunked + WS, `/dns/query`, cache flush, providers, UI hosting, store_dns).
  - `crates/honk-core/tests/config_dae_routing_test.rs` — end-to-end routing assertions against the root `config.dae` (**currently failing**, see status above).
  - Inline unit tests in `honk-core/src/control/*`, `routing/tests.rs`, `dns/*` (incl. `transport/tests_proto.rs` — DoT/DoH round-trips with rcgen self-signed certs; one `#[ignore]`d live Google DoH test), `relay/*`, `ebpf/real/tests.rs` (only with `ebpf` feature).
- Benchmarks: `cargo bench -p honk-core --bench dns`.
- The root-only netns/podman integration scripts referenced by older docs are not in this checkout.

## Configuration

The primary (and only documented) format is the original **dae syntax** — `{ include { ... } global { ... } node { ... } group { ... } routing { ... } dns { ... } subscription { ... } experimental { ... } }`, parsed by `honk-config/src/parser/mod.rs`. `include` accepts bare/quoted `.dae` glob patterns, resolves relative paths from the entry config directory, merges entry sections before included sections, and rejects repeated/cyclic or escaping files. Root examples: `config.dae` (full), `config.min.dae` (minimal), `example.dae` (annotated). Field-by-field reference: `doc/components.en.md`; guide: `doc/configuration.en.md`.

- Built-ins: outbound `direct` is auto-injected (by `honk-core`, not the parser) if missing; `block` drops traffic.
- Health checks via `global { tcp_check_url, udp_check_dns, check_interval, check_tolerance }`; dial modes `ip` / `domain` / `domain+` / `domain++`.
- DNS upstream URI schemes: `udp://` (bare default), `tcp://`, `tcp+udp://`, `tls://` (DoT), `https://` (DoH), `h3://`/`http3://` (DoH3), `quic://` (DoQ); optional dial-path proxy `name: 'uri' -> <node|group>` (or legacy `outbound:` key).
- Geo assets: `geoip.dat` / `geosite.dat` loaded at runtime (repo root is the common dev location).
- Environment variables: `RUST_LOG`, `HONK_UI_DOWNLOAD_URL` (UI zip override), `HONK_POOL_DISABLE=1` (bypass connection pool).
- Default runtime paths: config `/etc/honk/config.dae`, BPF pin root `/sys/fs/bpf`, embedded BPF object unless `--bpf-object`.

## Deployment

- **Native:** run `honk-core` as root (eBPF load, netns/veth creation, transparent TPROXY sockets, sysctl). The engine is self-contained: one config file, embedded eBPF object, optional clash API via `experimental.clash_api`.
- **Gateway / VyOS:** `just build-core` (or `build-musl` for a static `x86_64-unknown-linux-musl` binary — the workspace defines a `release-musl` profile) and copy the binary; `just deploy-vyos HOST=...` does musl build + scp + smoke run. The `just deploy` gateway script is not in this checkout.
- **Releases:** tag `v*` → GitHub Actions builds four targets and publishes tarballs (see CI above).
- **Docker:** the `Dockerfile` / `docker-compose.yml` referenced by the README and Justfile are not present in this tree; a container needs `--privileged --network=host --pid=host` and `/sys` mounted, and either an `ebpf`-feature build or `--bpf-object`/`--mock-ebpf`.
- **Cleanup:** stopping honk-core plus removing `dae0`/`daens`, BPF pins under `/sys/fs/bpf`, and policy routes (`just clean-all`) is sufficient — no global iptables rules are installed. **Never start a second instance while another is alive:** shutdown destroys the fixed-name datapath (dae0/daens/TC hooks) and a busy engine takes >90s to drain; the singleton flock at `/run/honk-core.lock` (held for the process lifetime) is the guard — a second instance waits for it instead of overlapping.

## Security considerations

- **Root/privileged execution:** `honk-core` must run as root to load eBPF programs, create `dae0`/`daens`, and bind transparent sockets.
- **Clash API secret:** when `experimental.clash_api` is enabled, set a strong `secret`; the REST/WS API has no TLS of its own — bind to localhost or front it with a reverse proxy.
- **Config trust:** `honk-core` runs `ip`/`sysctl` and loads a BPF object from configured/CLI paths. Treat config files and the BPF object as privileged input.
- **Bypass mark discipline:** `DAE_BYPASS_MARK` must stay on control-plane dial/probe/DNS sockets or the gateway loops its own traffic (see invariants above).

## Notes for agents

- Check which crate a file belongs to before assuming command context; `honk-ebpf` is **not** a workspace member (separate `Cargo.lock`, nightly-only target) — workspace-wide `cargo` commands skip it.
- When modifying eBPF map types or constants, update `honk-ebpf-common`, `honk-ebpf`, and the userspace map writers in `honk-core` together; struct layouts must stay in sync.
- Consult `doc/design.en.md` (architecture), `doc/configuration.en.md` / `doc/components.en.md` (config surface) before changing behavior; update them (both en and zh) when behavior changes.
- If you add or remove workspace crates, update this file and the root `Cargo.toml` `[workspace] members` list.
- The README contains an authorship disclosure: the eBPF datapath is the maintainer's primary focus; most userspace subsystems were largely AI-authored with partial review. Review userspace changes with corresponding care.

## ULW (UltraWork) Mode — Default Agent Behavior

> This project uses ULW mode by default, ported from [oh-my-openagent](https://github.com/code-yeongyu/oh-my-openagent).
> Type `ulw` or `ultrawork` in any prompt to activate full ultrawork orchestration.

### Agent roles

Use subagents to spawn specialized workers:

| Agent type | Role | Use when |
| ----------- | ------ | ---------- |
| `hephaestus` | Deep autonomous worker | Writing code, implementing features end-to-end |
| `prometheus` | Strategic planner | Complex multi-step tasks needing a plan first |
| `atlas` | Task orchestrator | Batch task execution with wisdom accumulation |
| `oracle` | Architecture consultant | Architecture decisions, complex debugging, security review |
| `Explore` (built-in) | Codebase grep | "Where is X defined?" / "Which files use Y?" |
| `librarian` | External docs researcher | Library APIs, OSS code search, latest docs |
| `metis` | Plan gap analyzer | Review plans before execution |
| `momus` | Ruthless plan reviewer | High-accuracy plan validation |
| `sisyphus-junior` | Task executor | Atomic tasks with clear instructions |

Model routing (see global `/skill:ulw` for full matrix + Backup rules):

| 职能 | Model | thinking | 典型 Agent |
| --- | --- | --- | --- |
| Coder | `kimi-coding/k3` | `high` | `hephaestus`, `sisyphus-junior` |
| Explore | `deepseek/deepseek-v4-flash` | `high` | `Explore`, locator/analyzer 族 |
| Web | `deepseek/deepseek-v4-pro` | `high` | `librarian`, `web-search-researcher` |
| Planner | `kimi-coding/k3` | `max` | `prometheus`, `Plan`, `atlas`, `metis` |
| Reviewer | `kimi-coding/k3` | `max` | `momus`, `oracle`, artifact/slice reviewers |
| Backup | `xai/grok-4.5` | `high` | `backup` agent（frontmatter 锁定；勿用 model 参数覆盖） |

### ULW principles

1. **Never stop halfway.** Complete the task or clearly report blockers.
2. **Delegate aggressively.** Use background agents for independent work.
3. **Verify before completion.** Run tests/lints/diagnostics before claiming done.
4. **Read before write.** Never modify a file without reading it first.
5. **Accumulate wisdom.** Pass learnings from earlier tasks to later ones.

### Commands for this project

```bash
cargo build --release          # Build workspace
cargo build --release -p honk-core
cargo test --all               # Run tests (see "Current test status" above!)
cargo clippy --all -- -D warnings
cargo fmt --all
```
