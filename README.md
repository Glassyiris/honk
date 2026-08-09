# honk

[English](./README.md) | [中文](./README_CN.md)

---

<a id="english"></a>

## What Is honk?

**honk** is a Rust transparent-proxy engine for Linux, inspired by [dae](https://github.com/daeuniverse/dae) for its eBPF datapath and configuration surface, and by [sing-box](https://github.com/SagerNet/sing-box) for its outbound groups, multi-protocol dialers, and Clash-compatible API.

It is **not** a line-for-line port of either project. The kernel path follows dae's TC + match_set + `dae0`/`daens` model, while the userspace outbound and control stacks follow sing-box-oriented designs. The project combines dae's datapath model with sing-box-inspired userspace behavior.

> **Status: experimental (`v0.0.1-alpha`).** honk is an early alpha release. Expect breaking changes, incomplete features (see TODO), and limited real-world validation. It is not recommended for production use.

License: **GPL-3.0-only**.

## Before Using This Repository

### Important: Review Status

These checkboxes indicate maintainer review status, not feature availability:

- [x] eBPF routing, maps, and semantics
- [x] Control plane
- [x] AnyTLS / Shadowsocks (including 2022) / SOCKS5
- [ ] RPRX (VLESS / XTLS / XHTTP / WSS / REALITY)
- [ ] Trojan-GFW (needs UoT implementation)
- [x] DNS logic
- [ ] Configuration parser (dae extensions)
- [ ] Reload logic
- [x] Tooling

### TODO

- [ ] Evaluate AF_XDP, XDP, and NFQUEUE paths for further performance gains
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
