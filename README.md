# honk

[English](./README.md) | [中文](./README_CN.md)

---

<a id="english"></a>

## English

**honk** is a Rust transparent-proxy engine for Linux, **inspired by** [dae](https://github.com/daeuniverse/dae) (eBPF datapath & config surface) and [sing-box](https://github.com/SagerNet/sing-box) (outbound groups, multi-protocol dialers, Clash-compatible API).

It is **not** a line-for-line port of either project. The kernel path follows dae’s TC + match_set + `dae0`/`daens` model; the userspace outbound/control stack follows sing-box-oriented designs. **honk** means: dae sing.

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

- [x] dae syntax load, include/glob composition & validate
- [x] Share-link parse (ss/socks5/vmess/vless/trojan/anytls/hy2/tuic/juicity/…)
- [x] Userspace `Router` (domain/IP/port/proto/process/MAC/geosite/geoip)
- [x] TCP sniff (TLS SNI, HTTP Host); QUIC Initial SNI decrypt
- [x] Dial modes `ip` / `domain` / `domain+` / `domain++`
- [x] Built-in `direct`/`block` node injection (reserved protocols, stable content-derived node IDs)

#### Outbound & groups

- [x] Handlers: Direct, Block, SOCKS5, SS(+2022), Trojan, VMess, VLESS, Hysteria2, TUIC, Juicity, AnyTLS
- [x] VLESS + REALITY client (incl. `xtls-rprx-vision` flow) over a patched-boring-sys ClientHello; Chrome-fingerprint JA4-aligned (ja4_a/ja4_b identical to real Chrome)
- [x] Shared transport (TLS/WS/gRPC)
- [x] Groups: Selector / URLTest / LoadBalance / Fallback + nested groups
- [x] URLTest: tolerance, separate TCP/UDP picks, idle_timeout, interrupt_connections
- [x] `AliveDialerSet`: concurrent probes, hysteresis, TCP+UDP probes, eBPF push
- [x] Subscription fetch + background merge (in-memory nodes)

### Review Status

- [x] ebpf pat
- [x] control plan
- [x] anytls / trojan / juicity /socks5
- [ ] ss/ vless/ vmess/ tuic
- [ ] dns logic
- [x] ech
- [ ] quic

### TODO

- [ ] UDP relay for VMess / VLESS
- [x] REALITY client + Chrome (uTLS-style) fingerprint — BoringSSL with a two-hook boring-sys patch; VLESS `xtls-rprx-vision` supported
- [x] Real DoT/DoH/DoQ/DoH3 upstreams (pooled TLS/H2/QUIC sessions)
- [x] Hysteria2 brutal (up/down Mbps), port hopping (`mport`/`mhop`), `pinSHA256`, QUIC receive-window/PMTUD knobs; live-verified against the official server
- [ ] Hysteria2 residue: `maxStreamReceiveWindow`/`maxConnReceiveWindow` (no quinn autotuning equivalent), `fastOpen`, configurable UDP-session/connection idle timeouts (hardcoded 90s/120s)
- [x] Consolidate QUIC client options: `QuicClientOptions` for transport tuning, `BoringQuicOptions` for the TLS backend
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
