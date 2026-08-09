# honk

[English](./README.md) | [中文](./README_CN.md)

---

<a id="english"></a>

## What Is honk?

**honk** is a Rust transparent-proxy engine for Linux, inspired by [dae](https://github.com/daeuniverse/dae) for its eBPF datapath and configuration surface, and by [sing-box](https://github.com/SagerNet/sing-box) for its outbound groups, multi-protocol dialers, and Clash-compatible API.

It is **not** a line-for-line port of either project. The kernel path follows dae's TC + match_set + `dae0`/`daens` model, while the userspace outbound and control stacks follow sing-box-oriented designs. The project combines dae's datapath model with sing-box-inspired userspace behavior.

> **Status: experimental (`v0.0.1-alpha`).** honk is an early alpha release. Expect breaking changes, incomplete features (see TODO), and limited real-world validation. It is not recommended for production use.

License: **GPL-3.0-only**.

## Experimental held-first-packet UDP decisions

The default-off UDP NFQUEUE path holds only ambiguous **LAN-forwarded** first packets after LAN TC and before conntrack/NAT. Enable it with a process configuration change:

```dae
experimental {
    udp_nfqueue {
        enabled: true
    }
}
```

Changing `experimental.udp_nfqueue.enabled` requires a restart. Enabled startup requires a build with the `ebpf` feature and the real eBPF backend; `--mock-ebpf` and builds without `ebpf` are rejected. Host-originated WAN egress remains on the canonical TPROXY path. DNS port 53, `must`, `block`, and already-safe route-time direct decisions never enter NFQUEUE; only decisions that can still change in userspace are staged.

The implementation owns one raw-netlink queue, number `320`, and the exact nftables objects `inet honk_nfqueue` / `udp_decision`; it uses no bypass, fanout, or fail-open option. Same-network-namespace firewall managers must not modify those objects while honk is running. Direct accepts each held original skb in FIFO order with its final mark and creates no userspace direct socket, payload copy, endpoint, connection entry, or deliberate retransmission. Proxy transfers its one retained payload copy into the normal UDP initializer, drops the originals, and dials/sends once; block and cancellation drop the originals.

When the Clash API is enabled, `GET /stats` exposes this path under `/stats.udp.nfqueue`: `received`, `activeFlows`, `directAccepted`, `proxyCopied`, `proxyDropped`, `block`, `cancel`, `drop`, `tokenMismatch`, `tokenExhaustion`, `verdictErrors`, and `receiptToVerdict`.

## Before Using This Repository

### Important: Review Status

These checkboxes indicate maintainer review status, not feature availability:

- [x] eBPF routing, maps, and semantics
- [x] Control plane
- [x] AnyTLS / Trojan / Shadowsocks (including 2022) / SOCKS5
- [ ] RPRX (VLESS / XTLS / XHTTP / WSS / REALITY)
- [x] DNS logic
- [ ] Configuration parser (dae extensions)
- [ ] Reload logic
- [x] Tooling

### TODO

- [ ] Evaluate AF_XDP and XDP paths for further performance gains
- [ ] Add a honk REST API
- [ ] Add a score-based group policy
- [ ] Add inbound support
- [ ] Track additional work through GitHub [Issues](https://github.com/Glassyiris/honk/issues) and [Discussions](https://github.com/Glassyiris/honk/discussions)

> No `test.1` release tag will be published until all currently unreviewed code has been reviewed and any unverified AI-generated implementation has been addressed.

## Acknowledgments

- [dae](https://github.com/daeuniverse/dae) / [daed-rs](https://github.com/daeuniverse/daed-rs) — eBPF transparent proxy lineage
- [sing-box](https://github.com/SagerNet/sing-box) — outbound group and Clash API patterns
- [daeuniverse/outbound](https://github.com/daeuniverse/outbound) — protocol reference
- [juicity-rs](https://github.com/juicity/juicity-rs) by Markson Pigeonzilla Plus — Juicity protocol implementation reference; the wire-format alignment and live interop testing of honk's Juicity outbound were done against it
- [aya-rs](https://github.com/aya-rs/aya) — Rust eBPF

## License

```text
SPDX-License-Identifier: GPL-3.0-only
Copyright (c) 2025, glassyiris <honk@catmint.cc> and honk contributors
```
