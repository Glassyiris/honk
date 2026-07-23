# honk

[English](./README.md) | [中文](./README_CN.md)

---

<a id="english"></a>

## English

**honk** is a Rust transparent-proxy engine for Linux, **inspired by** [dae](https://github.com/daeuniverse/dae) (eBPF datapath & config surface) and [sing-box](https://github.com/SagerNet/sing-box) (outbound groups, multi-protocol dialers, Clash-compatible API).

It is **not** a line-for-line port of either project. The kernel path follows dae’s TC + match_set + `dae0`/`daens` model; the userspace outbound/control stack follows sing-box-oriented designs.

> **Status: experimental (`v0.0.1.alpha`).** honk is an early alpha release — expect breaking changes, incomplete features (see TODO), and limited real-world validation. Not recommended for production use.

License: **GPL-3.0-only**.

### Documentation

| Doc                 | English                                              | 中文                                                 |
| ------------------- | ---------------------------------------------------- | ---------------------------------------------------- |
| Design              | [doc/design.en.md](./doc/design.en.md)               | [doc/design.zh.md](./doc/design.zh.md)               |
| Configuration       | [doc/configuration.en.md](./doc/configuration.en.md) | [doc/configuration.zh.md](./doc/configuration.zh.md) |
| Component reference | [doc/components.en.md](./doc/components.en.md)       | [doc/components.zh.md](./doc/components.zh.md)       |
| Index               | [doc/README.md](./doc/README.md)                     | same                                                 |

### Architecture (crates)

```text
crates/
├── honk-core/          # Engine binary: control plane, DNS, relay, Clash API, eBPF attach
├── honk-config/        # Config schema + dae-syntax parser + share links
├── honk-outbound/      # Proxy handlers, groups, health checks
├── honk-ebpf-common/   # Shared no_std #[repr(C)] types (kernel ↔ userspace)
└── honk-ebpf/          # Kernel eBPF programs (bpfel-unknown-none; outside workspace)
```

High-level path: **TC classify → redirect via `dae0`/`daens` → sk_lookup TPROXY listeners → userspace dial/relay**. Details in the design doc.

### Differences from dae (eBPF / control plane)

honk follows dae's kernel model but is not a port. The notable deltas:

**eBPF datapath**

- Toolchain: Rust [aya](https://github.com/aya-rs/aya) (`aya-ebpf` kernel side) instead of Go `cilium/ebpf`.
- LAN/WAN delivery is dae-parity, not a rewrite: the TC programs mark proxy-bound flows and redirect them into the `dae0` veth, then `sk_lookup` + `bpf_sk_assign` inside the `daens` netns hand them to the transparent listener sockets. Like Go dae, **no global `iptables` `TPROXY` rules are installed**.
- Kernel-side per-outbound accounting: a per-CPU `OUTBOUND_STATS` array (tx/rx packets/bytes per outbound) maintained by the TC programs; dae keeps no per-outbound counters in the kernel path.
- Routing fast path: at push time, userspace precomputes per-rule group masks for the four `(l4proto, ipversion)` groups (TCP4/TCP6/UDP4/UDP6) into `ROUTING_META_MAP`, and the eBPF route loop skips entire rule chains that cannot match the packet's group. dae's `route()` evaluates every match set sequentially; the core state machine here is otherwise a 1:1 port.
- Map design: conntrack / redirect-track / routing-handoff maps are **LRU** hash maps (auto-evict the oldest entry when full), while dae uses plain hash maps with count-on-overflow; the LPM tries are capped at 64K entries (~1.3 MB each) vs dae's 2M.

**Control plane**

- Management API: sing-box-style **Clash-compatible REST/WS API** instead of dae's GraphQL (`daed`).
- Groups: sing-box semantics — authoritative selection, nested sub-groups, URLTest with independent TCP/UDP picks, LoadBalance rotation, Fallback pinning; dae groups are flat with latency-based policies.
- Sniffing: TLS SNI / HTTP Host plus **QUIC Initial SNI decryption** (header-protection removal + crypto-stream reassembly); dae sniffs TLS/HTTP only.
- Persistence: SQLite `cachedb` (selector choices, clash mode, optional DNS answers) — dae keeps no such state across restarts.
- Reload/subscriptions: hot reload rebuilds the group manager through one serialized pipeline and migrates selector choices; subscription nodes merge in memory only, never written back to the config file.

### Authorship / contribution split

Please read this before attributing code quality or reviewing ownership:

| Area                                                                                                                       | Role of the project maintainer                                                                       |
| -------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| **eBPF datapath** (`honk-ebpf`, `honk-ebpf-common`, attach/maps path in `honk-core`)                                       | **Primary focus** — design participation, implementation checks, and verification                    |
| **Everything else** (config parsers, outbound protocols, groups/health, userspace DNS, Clash API, most control-plane glue) | **Mostly AI-authored**; maintainer did **partial code review** only, not full line-by-line ownership |

This is an intentional disclosure for users and future contributors.

### Completed and verified (summary)

Status reflects the current tree and unit/integration tests. Prefer re-running `cargo test --all` on your machine for a live gate.

#### eBPF / datapath (maintainer focus)

- [x] TC LAN/WAN ingress & egress (L2/L3), bond/bridge slave attach
- [x] `dae0` / `dae0peer` + `daens` delivery, `sk_lookup` + SockMap listeners
- [x] MatchSet routing machine, LPM (dest/src/MAC), domain bitmaps, must/OR/AND indices
- [x] Conntrack / redirect track / routing handoff maps
- [x] cgroup cookie→pid for process-name rules
- [x] DNS fast path (redirect DNS to userspace without full route loop)
- [x] Per-outbound `OUTBOUND_STATS` + `EVENT_RINGBUF` drain
- [x] Connectivity map fed by userspace health checks
- [x] Mock eBPF backend for unprivileged tests

#### Config & routing (userspace)

- [x] dae syntax load & validate
- [x] Share-link parse (ss/ssr/vmess/vless/trojan/anytls/hy2/tuic/juicity/…)
- [x] Userspace `Router` (domain/IP/port/proto/process/MAC/geosite/geoip)
- [x] TCP sniff (TLS SNI, HTTP Host); QUIC Initial SNI decrypt
- [x] Dial modes `ip` / `domain` / `domain+` / `domain++`
- [x] Built-in `direct` node injection; `block` outbound

#### Outbound & groups

- [x] Handlers: Direct, Block, SOCKS5, SS(+2022), SSR, Trojan, Trojan-Go, VMess, VLESS, Hysteria2, TUIC, Juicity, AnyTLS
- [x] Shared transport (TLS/WS/gRPC) + h2mux (`node.mux`)
- [x] Groups: Selector / URLTest / LoadBalance / Fallback + nested groups
- [x] URLTest: tolerance, separate TCP/UDP picks, idle_timeout, interrupt_connections
- [x] `AliveDialerSet`: concurrent probes, hysteresis, TCP+UDP probes, eBPF push
- [x] Subscription fetch + background merge (in-memory nodes)

#### Control plane extras

- [x] Splice TCP relay with copy fallback; UDP anyfrom replies
- [x] Clash-compatible REST/WS API (proxies, delay, connections, traffic, logs, DNS query, UI download)
- [x] SQLite cache (selector choices, mode, optional DNS persist)
- [x] Hot reload path rebuilds `GroupManager` and migrates selector choices

#### Tests / examples

- [x] Large unit/integration suite across `honk-config` / `honk-outbound` / `honk-core` (hundreds of tests; run `cargo test --all`)
- [x] Example configs kept parseable (`example.dae`, `config.dae`, `config.min.dae`)
- [x] Root-only netns/podman scripts under `scripts/` (environment-dependent)

### TODO

- [ ] UDP relay for VMess / VLESS / SSR / Trojan-Go
- [ ] REALITY + uTLS (**deferred** — no mature rustls hooks)
- [ ] smux/yamux; verified h2mux interop with official sing-box multiplex inbounds
- [x] Real DoT/DoH/DoQ/DoH3 upstreams (pooled TLS/H2/QUIC sessions)
- [ ] FakeIP engine
- [ ] Kernel-side eBPF DNS answer cache (userspace cache exists)
- [ ] Consistent-hash load balancing (round-robin LoadBalance exists)
- [ ] Broader live interop tests vs production peers; routine root-only netns gates

### Prerequisites

- Rust (edition 2024 / recent stable; eBPF object build needs **nightly** + `bpf-linker`)
- Linux kernel **5.8+** for real eBPF
- `clang`, `llvm`, `libbpf` headers for eBPF builds

```bash
# Debian/Ubuntu example
sudo apt-get install -y clang llvm libbpf-dev build-essential pkg-config
```

### Quick start

```bash
# Workspace
cargo build --release
cargo test --all

# Engine with real eBPF (root)
cargo build --release -p honk-core --features ebpf
sudo ./target/release/honk-core --config /etc/honk/config.dae

# Dev without kernel eBPF
cargo run --release -p honk-core -- --config config.dae --mock-ebpf
```

Day-to-day tasks: see `Justfile` (`just build-core`, `just run`, `just clean-all`, …).

### Docker

Default image builds `honk-core` without the `ebpf` feature (mock backend). For real eBPF, build with `--features ebpf` (nightly + bpf-linker in the build stage) or pass `--bpf-object`.

```bash
docker compose up -d
# privileged, host network, /sys + /etc/honk mounts — see docker-compose.yml
```

### Configuration (sketch)

```dae
global {
    tproxy_port: 12345
    lan_interface: eth0
    dial_mode: domain
}

node {
    trojan-node: 'trojan://secret@example.com:443'
}

group {
    proxy {
        filter: name(keyword: 'node')
        policy: min_moving_avg
    }
}

routing {
    domain(suffix: google.com) -> proxy
    fallback: direct
}
```

Full guides: [doc/configuration.en.md](./doc/configuration.en.md), [doc/components.en.md](./doc/components.en.md).

### Acknowledgments

- [dae](https://github.com/daeuniverse/dae) / [daed-rs](https://github.com/daeuniverse/daed-rs) — eBPF transparent proxy lineage
- [sing-box](https://github.com/SagerNet/sing-box) — outbound group & Clash API patterns
- [daeuniverse/outbound](https://github.com/daeuniverse/outbound) — protocol reference
- [juicity-rs](https://github.com/juicity/juicity-rs) by Markson Pigeonzilla Plus — Juicity protocol implementation reference; the wire-format alignment and live interop testing of honk's Juicity outbound were done against it
- [aya-rs](https://github.com/aya-rs/aya) — Rust eBPF

### License

```text
SPDX-License-Identifier: GPL-3.0-only
Copyright (c) 2025, glassyiris <honk@catmint.cc> and honk contributors
```
