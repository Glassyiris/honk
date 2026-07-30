# PROJECT KNOWLEDGE BASE

**Generated:** 2026-07-29
**Commit:** 3c8b74f
**Branch:** feat/analyze-dns

## OVERVIEW

`honk` is an experimental Rust transparent-proxy engine for Linux. The userspace engine combines a dae-style configuration/eBPF datapath with sing-box-oriented outbound groups, protocol dialers, DNS forwarding, and a Clash-compatible API.

Primary format: dae `{ section { ... } }` syntax. License: GPL-3.0-only. Rust edition: 2024.

## STRUCTURE

```text
.
├── crates/honk-config/       # Config schema, dae parser, share links
├── crates/honk-ebpf-common/  # no_std userspace/kernel ABI
├── crates/honk-outbound/     # Protocols, TLS/QUIC, groups, health
├── crates/honk-core/         # Engine, routing, DNS, API, eBPF loader
├── crates/honk-tool/         # Subscription probes and Linux diagnostics
├── crates/honk-ebpf/         # Excluded standalone kernel eBPF project
├── ci/                       # CI gates and Zig cross-build wrappers
├── doc/                      # Paired English/Chinese design and config docs
├── config.dae               # Full example
├── config.min.dae           # Mock-eBPF development example
└── Justfile                  # Canonical developer commands
```

Each crate has a local `AGENTS.md` with its domain-specific invariants. Read the nearest file before editing.

## WHERE TO LOOK

| Task | Location | Notes |
|---|---|---|
| Add/configure fields | `crates/honk-config/src/config.rs`, `node.rs`, `dns.rs` | Parser changes usually belong in `parser/mod.rs` |
| Parse subscriptions/share links | `crates/honk-config/src/share_link.rs` | Single parser for every supported scheme |
| Add/change a proxy protocol | `crates/honk-outbound/src/proxy/` | Registry contract lives in `proxy/mod.rs` |
| Change group selection/health | `crates/honk-outbound/src/group/`, `alive/` | TCP and UDP state are separate |
| Change startup/reload | `crates/honk-core/src/lib.rs`, `control/reload.rs` | Reload hot-swaps shared state |
| Change DNS behavior | `crates/honk-core/src/dns/`, `control/dns_control.rs` | One shared forwarder pipeline |
| Change userspace routing | `crates/honk-core/src/routing/`, `control/routing_matcher.rs` | Matcher compiles rules for eBPF |
| Change eBPF loading/maps | `crates/honk-core/src/ebpf/` | Real and mock backends must agree |
| Change kernel datapath | `crates/honk-ebpf/src/` | Separate nightly/BPF build |
| Change shared map ABI | `crates/honk-ebpf-common/src/` | Coordinate all three eBPF-facing crates |
| Change CLI diagnostics | `crates/honk-tool/src/` | Linux-only raw BPF/netns/API inspection |
| Change docs/config examples | `README*.md`, `doc/`, `*.dae` | Keep English/Chinese pairs aligned |

## CODE MAP

LSP was unavailable during generation because the configured nightly toolchain lacks `rust-analyzer`; reach below comes from the repository codegraph.

| Symbol | Location | Graph reach | Role |
|---|---|---:|---|
| `Node` | `crates/honk-config/src/node.rs:34` | 219 callers | Shared per-protocol and group schema |
| `Config` | `crates/honk-config/src/config.rs:12` | 89 refs | Root configuration loaded at startup/reload |
| `honk_core::run` | `crates/honk-core/src/lib.rs:248` | Entry flow | Config → backend → control plane |
| `ControlPlane::run` | `crates/honk-core/src/control/mod.rs:430` | Runtime hub | Listeners, routing, DNS, janitors, probes |
| `DnsForwarder::resolve` | `crates/honk-core/src/dns/forwarder.rs:160` | 27 callers | Cache/rules/upstream DNS pipeline |
| `ProxyRegistry::default_resolver` | `crates/honk-outbound/src/proxy/mod.rs:293` | 13 callers | Registers and dispatches all handlers |
| `SessionPool` | `crates/honk-outbound/src/session.rs:113` | 23 refs | Shared multiplexed-session lifecycle |
| `GroupManager::select_nodes_in_order_for_domain` | `crates/honk-outbound/src/group/selection.rs:102` | 9 callers | Authoritative policy selection |
| `Router::route` | `crates/honk-core/src/routing/mod.rs:298` | 6 callers | Userspace routing decision |
| `route` | `crates/honk-ebpf/src/route.rs:66` | 2 callers | Kernel MatchSet state machine |
| `OutboundIndex` | `crates/honk-ebpf-common/src/lib.rs:95` | ABI hub | Fixed outbound and sentinel IDs |

## CONVENTIONS

- Workspace members are `honk-config`, `honk-ebpf-common`, `honk-outbound`, `honk-core`, and `honk-tool`; `honk-ebpf` is explicitly excluded and has its own lockfile/toolchain.
- Stable Rust builds workspace code; kernel eBPF requires nightly, `rust-src`, `bpf-linker`, `-Zbuild-std=core`, and target `bpfel-unknown-none`.
- CI is the style authority: `cargo fmt --all -- --check` and `cargo clippy --all --all-targets -- -D warnings`.
- Use `tracing` structured fields. Comments document rationale, wire formats, invariants, or upstream parity; avoid section banners and narration.
- Application paths use `anyhow::Result`; reusable library errors use `thiserror`.
- Code comments and `.en.md` files are English; update the corresponding Chinese user documentation when behavior changes.
- BoringSSL builds from source and needs CMake, a C/C++ compiler, and libclang/bindgen.

## ANTI-PATTERNS (THIS PROJECT)

- Never change eBPF structs, enum widths, map keys, capacities, names, or program names in one crate only.
- Never use ordinary intercepted DNS or unmarked control-plane sockets for node/bootstrap dials; use the shared bootstrap resolver and `DAE_BYPASS_MARK`.
- Never publish a new routing rule count before the rule array and group bitmaps; count slot 0 is the commit switch.
- Never replace authoritative group policy picks with extra races or select a node dead in both UDP domains for UDP.
- Never make conntrack/redirect/handoff maps LRU: userspace state-aware janitors own eviction.
- Never advertise Hysteria2 `SETTINGS_H3_DATAGRAM`; it races the server UDP manager.
- Do not revive removed `sockops`/`sk_msg` eBPF stubs or use Aya `#[tc]` macros for current TC entrypoints.
- Do not use missing legacy `scripts/`, Docker assets, or old `just run`/`deploy` recipes.

## COMMANDS

```bash
cargo fmt --all -- --check
cargo clippy --all --all-targets -- -D warnings
just test-ci                         # CI-equivalent workspace tests
cargo test -p honk-config           # Target the touched crate
just outbound-ci                    # Outbound/config gate
just dns-ci                         # DNS/control/outbound gate
just clash-ci                       # Clash API/integration gate
just build-ebpf                     # Standalone eBPF + .BTF verification
cargo build --release -p honk-core --features ebpf
just run-dae                        # Unprivileged mock-eBPF run
```

## NOTES

- CI intentionally skips three known failures: two TOML round-trip tests in `honk-config` and `test_routing_with_config_dae`.
- Geo routing tests need `/etc/dae/geoip.dat` and `/etc/dae/geosite.dat`; unset `HTTP_PROXY`/`HTTPS_PROXY` for loopback UI tests.
- `crates/honk-ebpf/.cargo/config.toml` contains a machine-specific bpf-linker wrapper path; CI rewrites it to `bpf-linker`.
- `just clean-all` mutates live network/BPF state. Do not run it as a routine verification command.
- Root runtime defaults: `/etc/honk/config.dae`, BPF pins under `/sys/fs/bpf`; real eBPF execution requires root.
