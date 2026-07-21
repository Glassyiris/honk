# AGENTS.md — honk

This file is written for AI coding agents that need to understand, build, test, and modify the project. It describes the actual layout and conventions observed in the repository.

## Project overview

`honk` is a Rust reimplementation of [dae](https://github.com/daeuniverse/dae), the eBPF-based Linux transparent proxy. The goal is to provide:

- An eBPF transparent proxy engine (`honk-core`) that intercepts traffic with eBPF TC redirect (no global `iptables` rules), classifies it in eBPF, and relays it through proxy handlers in userspace.
- Shared configuration types and parsers (`honk-config`) that parse the original dae `{ section { ... } }` configuration syntax.

(The `honk-server` GraphQL API and `honk-web` Leptos dashboard crates were removed from the repository; the project now ships the proxy engine only.)

License: **GPL-3.0-only** (`SPDX-License-Identifier: GPL-3.0-only`).
Repository: <https://github.com/Glassyiris/honk>

## Repository layout

```text
.
├── Cargo.toml                 # Workspace manifest (release + release-musl profiles)
├── Makefile                   # Generic build/test/run tasks
├── Justfile                   # Day-to-day dev tasks (build, debug via clash API, deploy, cleanup)
├── run_tests.sh               # Per-crate test runner
├── test-honk.sh               # Root-only honk-core smoke runner with timeout + cleanup
├── Dockerfile                 # Multi-stage container build (honk-core only)
├── docker-compose.yml         # Compose deployment (privileged, host net)
├── plan.md                    # Consolidated unfinished design docs (health-check redesign, ...)
├── example.dae / config.dae / config.min.dae # Example dae-syntax configurations
├── scripts/                   # Root-only netns/podman integration tests + deploy helpers
├── log/                       # Captured logs from netns/podman test runs
├── crates/
│   ├── honk-config            # Shared config schema + parsers (workspace member)
│   ├── honk-ebpf-common       # no_std shared eBPF/userspace types (workspace member)
│   ├── honk-outbound          # Proxy handlers, groups, health checks (workspace member)
│   ├── honk-core              # eBPF proxy engine (workspace member)
│   └── honk-ebpf              # eBPF program crate (EXCLUDED from workspace)
├── daed/                      # Reference checkout: upstream daed dashboard (React/Vite/pnpm)
├── outbound/                  # Reference checkout: github.com/daeuniverse/outbound (Go)
└── sing-box/                  # Reference checkout: github.com/SagerNet/sing-box (Go)
```

> **Workspace note:** The root `Cargo.toml` includes `honk-config`, `honk-ebpf-common`, `honk-outbound`, and `honk-core` as workspace members and explicitly excludes `crates/honk-ebpf`.

> **Vendored reference repos:** `honk/`, `outbound/`, and `sing-box/` are independent git checkouts kept for protocol/behavior reference. They are **not** part of the Rust workspace, are not required to build anything, and changes there should not be mixed into Rust work. `honk/` is the upstream React dashboard with its own pnpm/Turbo monorepo and a `wing` submodule (the original Go backend).

## Technology stack

- **Language:** Rust edition 2024 (migrated from 2021 on Rust 1.96 stable).
- **Async runtime:** Tokio (`full`).
- **eBPF:** [aya-rs](https://github.com/aya-rs/aya) 0.14 (optional `ebpf` feature in `honk-core`); the eBPF program crate uses `aya-ebpf` 0.2 and targets `bpfel-unknown-none` (built with nightly + `-Zbuild-std=core`).
- **HTTP APIs:** axum 0.8 + tower-http 0.7 (optional `clash-api` feature in `honk-core`, on by default).
- **Persistence:** `honk-core` uses rusqlite 0.40 (`bundled`) for its persistent cache (`cachedb`).
- **TLS (outbound):** tokio-rustls 0.26 + rustls-pemfile + webpki-roots.
- **Serialization:** serde, toml 1, serde_json, serde_yaml.
- **Logging:** tracing + tracing-subscriber (`env-filter`, `json`); also `log`.
- **DNS:** self-contained forwarder (UDP/TCP/DoT/DoH/DoQ/DoH3) in `honk-core::dns`; no hickory dependency.
- **Error handling:** anyhow + thiserror 2.
- **HTTP client:** reqwest (rustls, no default features).

## Crate responsibilities

### `crates/honk-config`

Defines the configuration schema and parsers used by the rest of the project.

- `config.rs` — top-level `Config`/`GlobalConfig` structs and `from_file`/`to_file`/`validate` helpers. `ensure_builtin_nodes()` injects the built-in `direct` node at load/reload (maps to `DirectHandler` via the HTTP protocol), so `direct` works as a group member (`filter: name('direct')`, `groups`, `default`) without being declared in the config. `from_file`/`to_file` pick the format by file extension; the dae syntax is the primary format, while the TOML/YAML/JSON loaders remain for compatibility (undocumented).
- `experimental.rs` — `ExperimentalConfig` with `ClashApiConfig` (`external_controller`, `external_ui`, `secret`) and `CacheFileConfig` (`enabled`, `path`, `cache_id`, `store_fakeip`, `store_dns`; also parsed from the dae `experimental { ... }` section).
- `share_link.rs` — `Node::from_share_link`, the single share-link parser (SIP002 ss://, ssr:// base64 parameter blobs, vmess:// base64-JSON (v2rayN schema, ws/grpc/tls fields), trojan/trojan-go ws/grpc query params, AnyTLS pool params) used by the dae parser and `honk-core` subscriptions.
- `dns.rs` — `DnsConfig`, `DnsUpstream`, `DnsRouting`, `DnsStrategy`, `DnsCacheConfig`.
- `node.rs` / `group.rs` — `Node`, `Group`, `GroupPolicy`, plus node protocol field types. `Group.groups: Vec<String>` holds nested sub-group tags (sing-box style nested outbounds).
- `routing.rs` — `RoutingRule`, `RoutingCondition`, `RoutingOutbound`, `RoutingConfig`.
- `subscription.rs` — subscription configuration.
- `types.rs` — shared enums: `NodeProtocol`, `DialMode`, `OutboundIndex`, `SubscriptionType`, `DnsProtocol`.
- `parser/` — custom lexer/section parser (`lexer.rs`, `section_parser.rs`, `tests.rs`) that reads the original dae `{ global { ... } node { ... } routing { ... } }` syntax. Group sections accept `filter: group('tag'[, ...])` for nested sub-groups (routed into `Group.groups`); `resolve_group_filters` resolves only node filters (`name(...)`), and the filter-less "include all nodes" fallback applies solely when a group has neither filters nor sub-groups.
- `error.rs` — `ConfigError` type.

### `crates/honk-ebpf-common`

`#![no_std]` crate that contains constants and `#[repr(C)]` structs shared between the eBPF program and userspace `honk-core`. Both sides must agree on layout and map key sizes. Modules: `conn.rs` (`ConnTuple`, `TuplesKey`), `route.rs` (`RoutingResult`, `MatchSet`, `LpmKey`, `DomainKey`), `event.rs`, `redirect_need.rs`, `dae_ip.rs`, plus `DnsCacheEntry`, `OutboundStats`, `ParamKey`, `OutboundIndex`.

### `crates/honk-ebpf`

Separate Cargo project (**excluded from the workspace**, own `Cargo.lock`) that builds the kernel eBPF programs: TC LAN ingress / WAN ingress+egress, cgroup, `sk_lookup`, conntrack, routing, and DNS fast path (see `src/ingress.rs`, `egress.rs`, `cgroup.rs`, `sk_lookup.rs`, `contrack.rs`, `routing.rs`, `transport.rs`). Per-outbound traffic counters live in the per-CPU `OUTBOUND_STATS` array (index `outbound_stats_index(outbound, counter)` = `outbound * 4 + counter`, four `u64` slots: tx_packets/tx_bytes/rx_packets/rx_bytes — see `src/stats.rs`); tx is counted at `lan_ingress` when the routing decision lands (redirect and direct+must alike), rx at `dae0_ingress` using the outbound recorded in `RedirectEntry.outbound` at redirect time. `RealEbpfBackend` attaches `wan_ingress_l2/l3` to the WAN interface (L2/L3 by interface type, like `attach_wan_egress`; skipped in single-homed setups) and drains `EVENT_RINGBUF` (conntrack overflow `DaeEvent`s) into tracing on a background task. It has a custom `.cargo/config.toml` for the `bpfel-unknown-none` target whose `linker` points at a **machine-specific absolute path** (`/root/.cargo/bin/bpf-linker-wrapper`) — adjust it or install `bpf-linker` on a new machine. The crate builds to `target/bpfel-unknown-none/release/honk-ebpf`; `honk-core`'s `build.rs` embeds the object into the `honk-core` binary (built automatically with `cargo +nightly` when missing), and an external object can be supplied at runtime with `--bpf-object`. It is on Rust **edition 2024** (same as the workspace; verified building with nightly + `aya-ebpf` 0.2).

### `crates/honk-outbound`

Outbound dialing, groups, and health checking (extracted from `honk-core`).

- `proxy/` — the `ProxyHandler` trait/registry and per-protocol handlers: direct, block, socks5, shadowsocks (+ `shadowsocks_2022.rs` for `2022-blake3-*` methods, selected via `shadowsocks.rs::is_2022_method`), ssr, trojan, trojan-go, vmess, vless, hysteria2, anytls, tuic, juicity. `proxy/transport.rs` holds the shared stream-transport layer (TCP → optional TLS → optional h2mux or WebSocket/gRPC, driven by `node.mux`/`node.transport`/`ws_path`/`ws_host`/`grpc_service`) used by the trojan, vmess and vless handlers. `proxy/mux.rs` implements h2mux multiplexing (`node.mux = true`, h2mux only — no smux/yamux) behind that transport layer: a process-wide `MuxManager` caches HTTP/2 client sessions per `(host, port, tls, sni)`, prefixes the sing-mux session header (`0x00 0x02` = Version0+ProtocolH2Mux), opens one h2 stream per dial (`:method CONNECT`, `:authority localhost`, no `:path`/`:scheme`, 200 OK expected), reuses the least-loaded session below 8 active streams (sing-mux default `min_streams`), invalidates on GOAWAY/error with one redial attempt, and closes sessions idle (0 streams) for 60s. sing-box caveat: multiplex and WS/gRPC transport are mutually exclusive (mux wins, a debug log notes the ignored transport), and honk writes the proxy protocol header onto each h2 stream rather than using sing-mux's outer-handshake + per-stream `StreamRequest` layering, so official sing-box multiplex inbounds are not yet interop-verified. `anytls.rs` keeps a pool of multiplexed TLS sessions per node (sing-anytls semantics: one session carries many concurrent streams — a demux task dispatches frames by `sid`, an atomic allocator hands out stream ids, a stream ends with FIN, and the janitor reaps sessions that are stream-less and idle past the timeout), tuned by the node's `anytls_min_idle_session` / `anytls_idle_session_check_interval` / `anytls_idle_session_timeout` fields. `tuic.rs` (TUIC v5) and `juicity.rs` are QUIC handlers built on `quic.rs`: one shared QUIC connection per node (TLS-exporter auth on a uni stream, TCP = bi stream, TUIC UDP = datagrams with uni-stream fallback + fragmentation, Juicity UDP = length-framed bi stream), with per-session UDP bridges to local loopback socket pairs for `UdpProxySocket`. `hysteria2/` (handler in `mod.rs`, self-contained HTTP/3+QPACK layer in `h3.rs`, salamander obfuscation in `salamander.rs`) is also built on `quic.rs`: real QUIC wire protocol (ALPN `h3`) with a minimal self-contained HTTP/3 + QPACK layer for the `POST https://hysteria/auth` auth exchange (status 233), `0x401`-framed TCP streams, UDP over QUIC datagrams with sing-style fragmentation/reassembly, optional salamander obfuscation (`hy2_obfs`) via a custom quinn `AsyncUdpSocket` with a self-contained BLAKE2b-256, and BBR congestion (brutal needs bandwidth fields `Node` does not have).
  UDP relay handlers follow one pattern — `dial_udp` returns a loopback `UdpProxySocket` whose bridge task frames datagrams onto the tunnel (trojan UDP associate: `addr | u16 len | CRLF | payload` on a TLS-wrapped control stream, i.e. `trojan_udp_bridge`; anytls: sing UoT v2 — stream opened to `sp.v2.udp-over-tcp.arpa`, then `isConnect byte + destination in SOCKS5 form (sing's uot.ReadRequest uses M.SocksaddrSerializer, NOT the 0x00/0x01/0x02 per-packet AddrParser form)`, then bare `u16 len + payload` datagrams). `direct` is the only handler whose `relay_addr` is the target itself; every tunnel handler must bridge, or proxied UDP silently bypasses the tunnel and UDP health probes measure the gateway's own egress instead.
- `quic.rs` — shared QUIC client plumbing (quinn 0.11) for the QUIC-based outbounds: rustls/quinn `ClientConfig` assembly (ALPN, congestion control cubic/new_reno/bbr via quinn-proto factories), client `Endpoint` creation on `SO_MARK`'ed UDP sockets, the single-flight `QuicClient<C>` connection holder, and `QuicBiStream` (`AsyncRead + AsyncWrite` over a quinn stream pair).
- `alive/` — `AliveDialerSet` health checking: periodic TCP/UDP probes with per-protocol failure thresholds and latency history (the data URLTest selection sorts on). Each probe cycle runs the TCP probe (`probe_node`, HTTP via the injected `HttpProber` or raw connect) followed by a UDP probe (`probe_node_udp`) when honk-core has injected a `UdpProber` (`set_udp_probe`): honk-core's `ProxyUdpProber` sends a minimal DNS query to the first `global.udp_check_dns` target (default `8.8.8.8:53`) through the node's own `dial_udp` path, so a node with healthy TCP but broken UDP (e.g. an AnyTLS server without UoT) is marked dead on both UDP domains (success → `mark_alive_for_latency` on DataUdp+DnsUdp v4/v6 with the measured RTT; failure → one probe failure per UDP domain, threshold 3 + exponential backoff, gated in the cycle via `should_probe(DataUdp)`). UDP probes never touch TCP state and vice versa. `has_udp_state(node)` reports whether any UDP-domain state was ever recorded (probe or traffic report), which group selection uses to distinguish "never UDP-probed" from "UDP-probed and dead".
- `group/` — `GroupManager` (`mod.rs`: core types + `SharedGroupManager`; `selection.rs`: all policy selection logic): selector/urltest/loadbalance/fallback policies with **authoritative selection** (sing-box semantics): the dial path returns exactly the policy pick (manual Selector choice, current URLTest winner, rotated LoadBalance node, pinned Fallback node); the only multi-candidate race left is a URLTest group with no measurement data yet. **Nested groups** (sing-box style): `Group.groups` names sub-groups whose own policy pick contributes one member candidate each — candidates flatten recursively (depth cap `MAX_GROUP_DEPTH` = 8 + visited set; construction-time DFS cuts cycle-closing edges with a warning) and selection always resolves to a single leaf node. Member identity is the tag (node name or sub-group tag): `node_names_in_group` returns member tags (clash `all`, PUT `/proxies/{group}` targets), `leaf_node_names_in_group` expands to real nodes (health checks, eBPF connectivity aggregation), `delay_test_members` flattens to `(tag, leaf)` pairs for the delay endpoints, and `selection_chain` walks the current picks down to the leaf (RealTag-style debug view). URLTest keeps separate TCP/UDP selections (`SelectionNetwork`; UDP ranks by DataUDP→DnsUDP→TCP latency and mirrors the TCP selection when no UDP data exists) and is re-evaluated with tolerance hysteresis after every explicit delay test (clash-api delay endpoints) and on the dial path; LoadBalance rotates per-group via an independent `AtomicUsize` counter per group and never interrupts; Fallback pins the first alive member tag in declaration order until it dies (no immediate failback when a preferred node recovers). Selector-choice change callbacks (persisted by `honk-core` via `cachedb`), `interrupt_connections` interruption on selection changes, and URLTest idle sleep (`idle_timeout` stops health checks for idle groups). `SharedGroupManager` (`Arc<RwLock<Arc<GroupManager>>>`) is the hot-swappable cell the control plane, connection handles, and clash API share; config reload swaps in a rebuilt manager and migrates surviving selector choices (`migrate_selector_choices_from` — valid for node-targeted and sub-group-targeted choices alike). **UDP candidate exclusion** (`filter_alive_candidates`): per node, DataUDP or DnsUDP alive → selectable; BOTH UDP domains explicitly dead → excluded even when TCP is alive (no TCP fallback — a TCP-only node must not attract UDP flows); node never UDP-probed (`!AliveDialerSet::has_udp_state`) → inherits TCP liveness (the legacy fallback, kept for setups without UDP probing).
- `urltest.rs` — on-demand URLTest latency measurement (sing-box semantics) backing the clash API delay endpoints; failures clear the node's latency history so it sorts last.
- `tls.rs` — shared TLS client configuration helpers.

### `crates/honk-core`

The proxy engine (library + `honk-core` binary). Cargo features:

- `default = ["clash-api"]`
- `ebpf` — real eBPF backend via aya (requires Linux kernel 5.8+); without it the engine runs on `MockEbpfBackend`.
- `clash-api` — Clash-compatible REST/WS API (both API features pull in optional axum/tower-http deps).

`build.rs` (only active with the `ebpf` feature) locates or builds the eBPF object and copies it into `OUT_DIR` as `honk-ebpf.o`; `lib.rs` embeds it with `include_bytes!(env!("HONK_EBPF_OBJECT"))`.

Major modules:

- `control/` — the control plane: `ControlPlane` accept loop (`mod.rs`), connection handling (`connection.rs`), config reload pipeline (`reload.rs`), TPROXY/UDP reply sockets (`sockets.rs`), health probers (`probers.rs`), command channel, connection draining, DNS control, routing matcher push, janitors, UDP endpoint pool, packet sniffing helpers, interface binding. Proxied-UDP replies are sent back to LAN clients from a per-endpoint "anyfrom" transparent socket bound to the flow's original destination (Go dae parity; `new_udp_reply_socket` in `control/sockets.rs`, cached on the endpoint in `udp_endpoint.rs`) — falling back to the TPROXY listener socket makes replies die in the host dae0 path with source `169.254.0.11:<tproxy_port>`.
- `dns/` — DNS resolver, cache, forwarder, upstream pool, listener, DNS routing, and `persist.rs` (optional `store_dns` persistence: a background batch writer mirroring `DnsCache` inserts into cache.db, plus startup restore).
- `ebpf/` — `EbpfBackend` trait, in-memory `MockEbpfBackend` (`mock.rs`), and `RealEbpfBackend` (`real/`, gated by the `ebpf` feature; `real/syscall.rs` raw BPF syscalls, `real/attach.rs` program load/attach, `real/events.rs` EVENT_RINGBUF draining), plus map helpers (`maps.rs`) and kernel probing (`probe.rs`).
- `relay/` — TCP splicing/relay and UDP relay utilities.
- `routing/` — userspace routing engine (`Router` in `mod.rs`, LPM trie in `lpm.rs`, geoip/geosite matchers in `geo.rs`) compiled from `RoutingRule`s.
- `sniffing.rs` — TLS SNI and HTTP Host sniffing from initial TCP bytes.
- `stats.rs` — per-outbound connection/byte/error statistics.
- `pool.rs` — TCP connection pool for proxy dials (bare pre-handshake streams and fully-dialed "ready" tunnels).
- `connection_tracker.rs` — per-connection state tracker feeding the clash API `/connections`.
- `subscription.rs` — subscription fetching/parsing (share links decoded via `Node::from_share_link`). Startup fetches race a 5-second deadline in `run()`; late completions and per-subscription periodic refreshes (`Subscription.update_interval`, default 86400s, 0 = manual) merge through `ControlCommand::MergeSubscription`, which replaces that subscription's nodes (matched by `subscription_id`), re-resolves group membership, and reuses the same serialized rebuild pipeline as SIGHUP reloads (`apply_runtime_config`). Subscription nodes live in memory only, never written back to the config file.
- `cachedb.rs` — persistent SQLite cache (selector choices, clash mode, and — when `cache_file.store_dns` is set — DNS answers under the `dns:` kv prefix with lazy expiry) opened via `experimental.cache_file` (rusqlite, bundled).
- `mode.rs` — shared clash mode state (`ModeState`: Rule/Global/Direct + GLOBAL selection), held by both the control plane (mode override on the outbound decision) and the clash API.
- `clash_api.rs` + `clash_api/{logs,doh,ui}.rs` — Clash-compatible REST/WS API (sing-box `experimental/clashapi` minimal set), started when `experimental.clash_api.external_controller` is set. `clash_api/logs.rs` is the tracing broadcast layer feeding `/logs`. Includes on-demand delay endpoints (`/proxies/{name}/delay`, `/group/{name}/delay`) backed by `honk-outbound::urltest`, `/dns/query` (DoH-style JSON via the control-plane DNS forwarder, parsing in `clash_api/doh.rs`), `/providers/proxies` (each group exposed as a proxy provider), chunked-HTTP fallbacks for `/logs` and `/traffic` on non-WS requests, and external-UI auto-download (`clash_api/ui.rs`: background Yacd-meta zip download into an empty/missing `external_ui` dir, `HONK_UI_DOWNLOAD_URL` override; failures only warn).

The `honk-core` binary (`src/main.rs`) parses `Cli` (from `lib.rs`) and either runs a **clash-style subcommand** (`mode`, `proxy`, `delay` — edit/save config or query a running controller) or starts the engine. CLI flags: `--config` (default `/etc/honk/config.dae`), `--bpf-object`, `--bpf-pin-root` (default `/sys/fs/bpf`), `--debug`, `--mock-ebpf`.

Proxy handlers, groups, and health checks live in `honk-outbound` (above), not in this crate.

Runtime flow (high level):

1. The eBPF LAN ingress program classifies each new TCP SYN / UDP datagram, marks proxy-bound flows with `tproxy_mark`, and tc-redirects them into the `dae0` veth. Inside the `daens` netns, policy routing plus the `sk_lookup` program and the `dae0peer` TC ingress program (`bpf_sk_assign`) deliver them to the transparent (TPROXY) listener sockets bound there, preserving the original destination. Like Go dae, **no global `iptables` TPROXY/PREROUTING rules are installed**.
2. `honk-core` binds to that port and reads the original destination (`SO_ORIGINAL_DST` / `IP_ORIGINAL_DSTADDR`).
3. It looks up an eBPF routing handoff entry; if absent it falls back to the userspace `Router`.
4. It sniffs TLS SNI / HTTP Host to obtain a domain for domain-based rules.
5. It resolves the target, selects the node/group, dials through the appropriate `ProxyHandler`, and relays traffic bidirectionally.
6. DNS queries can take a fast path through the internal DNS forwarder/resolver (also accelerated by an eBPF DNS fast path).

## Build and test commands

### Rust workspace

```bash
# Check / build workspace members
cargo check
cargo build --release

# Individual workspace crates
cargo build --release -p honk-config
cargo build --release -p honk-ebpf-common
cargo build --release -p honk-outbound
cargo build --release -p honk-core

# Run tests for the workspace members (verified: 603 tests, all passing)
cargo test --all

# The repo also provides a convenience test script
./run_tests.sh
```

### `honk-core` with real eBPF

```bash
# Requires Linux kernel 5.8+, clang, llvm, libbpf-dev, and the ebpf feature.
# build.rs auto-builds the eBPF object with the nightly toolchain on first build.
cargo build --release -p honk-core --features ebpf

# Run as root (TPROXY + eBPF require privileges).
# The eBPF object file is embedded into the binary, so --bpf-object is optional.
sudo ./target/release/honk-core --config /etc/honk/config.dae

# To use an external object file instead of the built-in one:
sudo ./target/release/honk-core \
    --config /etc/honk/config.dae \
    --bpf-object /etc/honk/honk-core.o
```

Without the `ebpf` feature, `honk-core` runs with the `MockEbpfBackend` and can be started for testing:

```bash
cargo run --release -p honk-core -- \
    --config config.dae \
    --mock-ebpf
```

### eBPF program

```bash
cd crates/honk-ebpf
cargo +nightly build --release -Zbuild-std=core --target bpfel-unknown-none
# Produces the object at target/bpfel-unknown-none/release/honk-ebpf
```

This crate assumes a nightly toolchain and `bpf-linker` (the `.cargo/config.toml` references a `bpf-linker-wrapper` by absolute path — see the crate section above).

### Justfile (preferred for day-to-day dev)

`just` is the task runner used for real-device work. Key recipes:

| Recipe | Purpose |
| -------- | --------- |
| `build` | `cargo build --release` (whole workspace) |
| `build-core` | `honk-core` with `ebpf` (+ default `clash-api`) |
| `build-core-ebpf` | `honk-core` with `ebpf` only |
| `build-musl` | static musl build of `honk-core` for VyOS/Debian (sources `scripts/musl-env.sh`, target `x86_64-unknown-linux-musl`) |
| `build-ebpf` | build the eBPF object standalone (nightly, `bpfel-unknown-none`) |
| `run` / `run-debug` | run `honk-core` locally via `scripts/debug-local.sh` (clash API on :9090) |
| `run-dae` | run `honk-core` with `config.dae` + `--mock-ebpf` |
| `debug-status` / `debug-config` / `debug-alive` / `debug-stats` / `watch-debug` | query the clash HTTP API (`/version`, `/proxies`, `/group/{n}/delay`, `/stats`, `/connections`) |
| `bpf-progs` / `bpf-maps` | inspect loaded BPF programs and pinned maps |
| `deploy HOST=...` | build + deploy to a gateway (default `10.10.10.1`) via `scripts/deploy-gateway.sh` |
| `deploy-vyos HOST=...` | musl build + scp to a VyOS router |
| `clean-all` | kill `honk-core`, remove `dae0`/`daens`, BPF pins, iptables MASQUERADE rules, policy routes |
| `cycle` | `clean-all` + `build-core` |

### Makefile targets

| Target | Purpose |
| -------- | --------- |
| `all`, `build` | Build Rust workspace release binaries |
| `build-core` | Build `honk-core` (no features) |
| `test` | `cargo test --all` |
| `fmt` | `cargo fmt --all` |
| `lint` | `cargo clippy --all -- -D warnings` |
| `clean` | `cargo clean` |
| `docker` / `docker-up` / `docker-down` | Docker image and compose helpers |
| `outdated` / `audit` | `cargo outdated` / `cargo audit` |
| `doc` | `cargo doc --no-deps --open` |

### JavaScript frontend (`honk/`, reference only)

```bash
cd honk
pnpm install
pnpm dev        # start Vite dev server
pnpm build      # production build via turbo
pnpm test       # vitest via turbo
pnpm lint       # eslint --fix
pnpm codegen    # graphql-codegen
```

## Code style guidelines

- Rust source files do **not** carry SPDX/copyright headers; licensing and attribution live in the root `README.md` only.
- Keep comments minimal: module-level `//!` docs (purpose + non-obvious architecture), `///` docs on public items, and "why" comments (rationale, invariants, wire formats, upstream parity notes, past-bug warnings). No section banners, no comments that restate the code.
- Prefer `anyhow::Result<()>` for application/binaries and `thiserror` for library error types.
- Use `tracing` macros for logging; prefer structured fields where useful (`info!(network = "tcp", outbound = %name, ...)`).
- Use `tokio` async/await and `tokio::select!` for long-lived loops.
- eBPF-related structs that cross the kernel/userspace boundary live in `honk-ebpf-common` and must be `#[repr(C)]` with stable layouts.
- Follow `cargo fmt` formatting and keep `cargo clippy --all -- -D warnings` clean.

## Testing instructions

- `cargo test --all` runs unit and integration tests for workspace members (last verified: 603 tests, all passing, no root required).
- `./run_tests.sh` performs per-crate `cargo check` and targeted `cargo test` runs for `honk-config`, `honk-ebpf-common`, and `honk-core`.
- `honk-core` tests rely on `MockEbpfBackend` so they do **not** require a kernel with eBPF support or root privileges.
- Test locations:
  - `crates/honk-core/tests/integration_test.rs` — configuration loading/validation, routing (domain suffix, IP CIDR, default fallback), mock eBPF backend workflow, SOCKS5/direct/block proxy handlers, TCP relay, DNS resolver creation, statistics manager, control-plane command channel.
  - `crates/honk-core/tests/clash_api_test.rs` — Clash API endpoints.
  - `crates/honk-core/tests/config_dae_routing_test.rs` — dae-syntax config + routing integration.
  - `crates/honk-config/tests/example_configs.rs` — keeps the root example config files parseable.
  - `crates/honk-config/tests/share_link.rs` — share-link parsing.
  - `crates/honk-config/src/parser/tests.rs` — dae-syntax lexer/parser unit tests.
- Root-only end-to-end scripts (require root, network namespaces / podman, real eBPF): `test-honk.sh` (smoke runner with timeout + cleanup), `scripts/test-netns*.sh`, `scripts/test-podman-honk.sh`. Their captured output lives in `log/`. `scripts/cleanup-honk.sh` / `scripts/cleanup.sh` remove the resulting system state.

## Configuration

The primary (and only documented) configuration format is the original **dae syntax** — `{ global { ... } node { ... } routing { ... } }`, parsed by `honk-config/src/parser/` (see the root examples `config.dae` and `config.min.dae`, kept parseable by `crates/honk-config/tests/example_configs.rs`).

Important configuration sections:

- `global { ... }` — `tproxy_port`, `tproxy_mark`, `log_level`, `lan_interface`, `auto_config_kernel_parameter`, health-check URLs/intervals, etc.
- `node { ... }` / `group { ... }` — proxy nodes and load-balancing groups.
- `routing { ... }` — ordered rules matching domain, IP/CIDR, port, protocol, process name, MAC, geosite, geoip, ending in a `fallback:`.
- `dns { ... }` — upstreams, routing, cache.
- `subscription { ... }` — subscription URLs.
- `experimental { ... }` — `clash_api.external_controller` / `clash_api.secret`, `cache_file`.

Default runtime paths:

- `honk-core`: config `/etc/honk/config.dae`, built-in BPF object (external override via `--bpf-object`), pin root `/sys/fs/bpf`.

## Deployment processes

### Native

Run `honk-core` as root (it needs eBPF, network namespaces, and transparent TPROXY sockets). The engine is self-contained: it reads a single config file (`--config`, default `/etc/honk/config.dae`), embeds the eBPF object, and optionally exposes the Clash-compatible API via `[experimental.clash_api]`.

### Gateway / VyOS

`just deploy [HOST]` (default `10.10.10.1`) builds `honk-core` with `ebpf` and runs `scripts/deploy-gateway.sh` (strip + scp + restart). `just deploy-vyos [HOST]` cross-compiles a static musl binary (`scripts/musl-env.sh` sets up the cross toolchain on NixOS) and installs it on a VyOS router. The workspace Cargo.toml defines a `release-musl` profile for portable static builds.

### Docker

The multi-stage `Dockerfile` builds only `honk-core` (`cargo build --release -p honk-core`, default features) and uses it as the container entrypoint (`--config /etc/honk/config.dae`). A container built this way runs the mock eBPF backend; for real eBPF builds add `--features ebpf` (which additionally needs a nightly toolchain + `bpf-linker` in the build stage) or bind-mount an external object and pass `--bpf-object`.

Example container run (privileged, host network):

```bash
docker run -d \
    --privileged \
    --network=host \
    --pid=host \
    --restart=always \
    -v /sys:/sys \
    -v /etc/honk:/etc/honk \
    honk:latest
```

### Docker Compose

`docker-compose.yml` uses the prebuilt image `ghcr.io/daeuniverse/honk:latest` with `privileged: true`, `network_mode: host`, `pid: host`, and mounts `/sys` and `/etc/honk`. Run `docker compose up -d`.

## Security considerations

- **Root/privileged execution:** `honk-core` must run as root to load eBPF programs, create `dae0` veth pairs / netns, and bind `TPROXY` sockets. The Docker deployment uses `--privileged`, `--network=host`, and `--pid=host`.
- **Clash API secret:** when `[experimental.clash_api]` is enabled, set a strong `secret`; the REST/WS API has no TLS of its own — front it with a reverse proxy if exposed beyond localhost.
- **Config trust:** `honk-core` runs `ip` and loads a BPF object from paths supplied by configuration. Treat config files and the BPF object as privileged input.

## Notes for agents

- Always check whether a file is in `crates/honk-config`, `crates/honk-ebpf-common`, `crates/honk-outbound`, `crates/honk-core`, or one of the reference checkouts (`honk/`, `outbound/`, `sing-box/`) before assuming a command context.
- When modifying eBPF map types or constants, update both `honk-ebpf-common` and the eBPF program in `crates/honk-ebpf`; struct layouts must stay in sync.
- LAN delivery follows Go dae (tc redirect to `dae0` + `sk_lookup`/`bpf_sk_assign` in `daens`); no `iptables` TPROXY rules are installed, so cleanup only needs to remove `dae0`/`daens`, policy routes, and BPF pins.
- The userspace relay has two paths: connections where both ends are plain `TcpStream`s (direct dial) relay zero-copy via `splice(2)` (`relay::splice::relay_splice`, bidirectional with half-close propagation); TLS/protocol-wrapped streams use `tokio::io::copy_bidirectional` (`relay::splice::relay_auto` → `relay_tcp`). If the kernel rejects `splice(2)` (EINVAL/ENOSYS/EXDEV on the first probe, before any byte is moved) the connection falls back to copy and a process-wide flag latches so later connections skip probing. Do not bypass the probe/fallback logic; the old unidirectional splice path caused timeouts and must not return.
- If you add or remove workspace crates, update this file and the root `Cargo.toml` `[workspace] members` list accordingly.
- `plan.md` collects unfinished design work (e.g. the health-check/node-selection redesign inspired by sing-box URLTest/Selector). Consult it before reimplementing those subsystems.
- The reference checkouts (`honk/`, `outbound/`, `sing-box/`) have their own upstream conventions; do not edit them as part of Rust changes.

## ULW (UltraWork) Mode — Default Agent Behavior

> This project uses ULW mode by default, ported from [oh-my-openagent](https://github.com/code-yeongyu/oh-my-openagent).
> Type `ulw` or `ultrawork` in any prompt to activate full ultrawork orchestration.

### Agent Roles Available

Use the `Agent` tool (pi-subagents) to spawn specialized workers:

| Agent Type | Role | Use When |
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

### Default Model Assignments

All agents use DeepSeek models (current default provider):

| Agent | Model | Thinking |
| ------- | ------- | ---------- |
| Main/Sisyphus | `deepseek/deepseek-v4-pro` | xhigh |
| hephaestus | `deepseek/deepseek-v4-pro` | xhigh |
| prometheus | `deepseek/deepseek-v4-pro` | high |
| atlas | `deepseek/deepseek-v4-pro` | medium |
| oracle | `deepseek/deepseek-v4-pro` | xhigh |
| librarian | `deepseek/deepseek-chat` | low |
| metis | `deepseek/deepseek-v4-pro` | medium |
| momus | `deepseek/deepseek-v4-pro` | high |
| sisyphus-junior | `deepseek/deepseek-v4-pro` | low |

### ULW Principles

1. **Never stop halfway.** Complete the task or clearly report blockers.
2. **Delegate aggressively.** Use background agents for independent work.
3. **Verify before completion.** Run tests/lints/diagnostics before claiming done.
4. **Read before write.** Never modify a file without reading it first.
5. **Accumulate wisdom.** Pass learnings from earlier tasks to later ones.

### Commands for this project

```bash
# Build workspace
cargo build --release

# Build specific crates
cargo build --release -p honk-config
cargo build --release -p honk-core

# Run tests
cargo test --all
./run_tests.sh

# Lint
cargo clippy --all -- -D warnings

# Format
cargo fmt --all
```
