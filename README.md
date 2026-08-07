# honk

[English](./README.md) | [中文](./README_CN.md)

---

<a id="english"></a>

## Honk is What

**honk** is a Rust transparent-proxy engine for Linux, **inspired by** [dae](https://github.com/daeuniverse/dae) (eBPF datapath & config surface) and [sing-box](https://github.com/SagerNet/sing-box) (outbound groups, multi-protocol dialers, Clash-compatible API).

It is **not** a line-for-line port of either project. The kernel path follows dae’s TC + match_set + `dae0`/`daens` model; the userspace outbound/control stack follows sing-box-oriented designs. **honk** means: dae sing.

> **Status: experimental (`v0.0.1.alpha`).** honk is an early alpha release — expect breaking changes, incomplete features (see TODO), and limited real-world validation. Not recommended for production use.

License: **GPL-3.0-only**.

## What we should know befaore using this repo

### important: review status

- [x] ebpf routing / map / semantics
- [x] control plane
- [x] anytls / trojan / ss(2022) / socks5
- [ ] rprx(vless / xtls / xhttp / wss / reality)
- [x] dns logic
- [ ] config parser(dae extend)
- [ ] reload logic
- [x] tool

### todo

- [ ] fakeip? maybe
- [ ] AF_XDP / XDP / TC / NFQUE to make honk more efficient
- [ ] Honk restful api
- [ ] score based group policy
- [ ] honk inbound
      .... or any from _issue_ or _discuss_

> **before i review all code which is not yet ready for production use(without vibe coding), will not release tag: test.1**

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
