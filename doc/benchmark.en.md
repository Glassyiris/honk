# Benchmark Lab and Results

This document describes the reproducible benchmark environment for honk and
the most recent results against [dae](https://github.com/daeuniverse/dae)
(same-time A/B). It lives in the repo so the setup and the numbers stay in
sync with the code.

## Lab topology

```text
┌─────────────────────────────┐         ┌─────────────────────────────┐
│ 10.10.10.50 (VM, 4C/2G)     │         │ 10.10.10.70 (physical, 50G) │
│                             │         │                             │
│  ┌───────────────┐          │  LAN    │  Protocol servers:          │
│  │ netns "lab"   │ veth     ├────────►│   hy2        :8443/udp      │
│  │ 192.168.222.2 ├──────────┤         │   tuic       :2444/udp      │
│  └───────┬───────┘          │         │   anytls-sb  :2445/tcp      │
│          │ NAT + TPROXY     │         │   anytls-go  :2443/tcp      │
│  honk / dae (one at a time) │         │   ss-2022    :2447/tcp      │
│  lan_ifname: veth-lab       │         │   trojan     :2446/tcp      │
│  wan_ifname: ens3           │         │  Targets:                   │
└─────────────────────────────┘         │   http       :8001-8006     │
                                        │   iperf3     :5201-5206     │
                                        │   udp echo   :53530         │
                                        └─────────────────────────────┘
```

- **Engine host (10.10.10.50)**: runs either honk or dae (never both). The
  client lives in network namespace `lab` (veth pair `veth-lab` ↔
  `veth-client`, 192.168.222.0/24, NAT via nftables masquerade). All client
  traffic crosses the engine's real eBPF datapath, so numbers include the
  full kernel path, not a loopback shortcut.
- **Server host (10.10.10.70)**: protocol servers (official hysteria,
  tuic-server, sing-box, Go anytls-server) plus local targets. Servers dial
  out to the internet directly, so "internet" tests traverse server → WAN.
- **Isolation**: nothing here touches the production gateway (10.10.10.1).
  Production validations are done separately and called out as such.

### Known lab limits

- Both VMs have single-queue virtio NICs. VM↔VM throughput caps around
  0.8–1.7 Gbps TX; physical↔VM reaches 9.4 Gbps. For bandwidth runs the
  servers therefore live on the **physical** host: client RX (9.4 Gbps) is
  the ceiling, not the inter-VM link. Direct baseline (engine direct path +
  NAT): **9.39–9.41 Gbps**.
- Run-to-run variance on shared infrastructure is ±5%; stall-type artifacts
  on WAN subscriptions (nexi) fluctuate on multi-minute windows and are not
  engine regressions — see "Production notes" below.

## What's running where

| Component | Binary | Config |
| --- | --- | --- |
| hy2 server | official `hysteria` | `:8443`, password `testpass123`, cert CN `hy2.test` |
| TUIC server | `tuic-server` 1.0.0 | `:2444`, uuid `00000000-0000-0000-0000-000000000001` / `testpass123`, requires SNI `hy2.test` |
| AnyTLS server | sing-box | `:2445`, password `testpass123` |
| AnyTLS server | Go reference `anytls-server` | `:2443`, `-p testpass123` |
| SS 2022 server | sing-box | `:2447`, `2022-blake3-aes-128-gcm`, psk `8JCsHssyVTFyPy5lYdNhZg==` |
| Trojan server | sing-box | `:2446`, password `testpass123`, SNI `hy2.test` |
| Targets | python http.server, iperf3 | ports `8001-8006`, `5201-5206`; UDP echo `:53530` |

Engine configs route by destination port so no API switching is needed:
`5201/8001 → hy2`, `5202/8002 → tuic`, `5203/8003 → ss2022`,
`5204/8004 → trojan`, `5205/8005 → anytls-sb`, `5206/8006 → anytls-go`
(honk only — dae has no AnyTLS). Node server ports are `direct(must)`.

## How to run

All scripts live on the engine host in `/root` (source copies in
`/tmp/lab-bin` on the operator machine).

```bash
# Protocol correctness matrix (TCP target / UDP echo / internet per protocol)
bash /root/test-protocols.sh

# Full benchmark: per protocol — cold/warm first-request latency,
# iperf3 download bandwidth, engine CPU% and RSS during the run
bash /root/bench.sh honk 'hy2 tuic ss2022 trojan anytls-sb anytls-go'
bash /root/bench.sh dae  'hy2 tuic ss2022 trojan'

# Cold first-connect latency with health checks effectively off (3600s)
bash /root/bench-cold.sh

# P0 acceptance: 100k random 5-tuple UDP flood, resource bounds + fallback
bash /root/flood-test.sh 100000 20000
```

## Results (2026-07-29, honk v0.0.1.beta.22)

### Bandwidth (iperf3 `-R`, single stream, 8s; direct baseline 9.41 Gbps)

| Protocol | dae | honk | honk/dae |
| --- | --- | --- | --- |
| hy2 | 2.06 Gbps | 1.86 Gbps | 90% |
| tuic | 2.63 Gbps | 2.01 Gbps | 76% |
| ss2022 (before/after codec rewrite) | 1.51 Gbps | 0.87 → **1.33 Gbps** | 88% |
| trojan | 4.18 Gbps | 4.00 Gbps | 96% |
| anytls (sing-box server) | — | 3.09 Gbps | — |
| anytls (Go server) | — | 3.21 Gbps | — |
| ss2022 4-stream | 5.51 Gbps | 5.05 Gbps | 92% |

### Three-way (2026-07-29, honk v0.0.1.beta.23 + sing-box 1.13.14)

Same-time A/B/C. CPU in parentheses = cores used during the run; cold =
first request after engine start.

| Protocol | dae | sing-box | honk |
| --- | --- | --- | --- |
| hy2 | 2.10 Gbps (1.28c) | 2.10 Gbps (1.58c) | 1.93 Gbps (0.97c) |
| tuic | 1.80 Gbps (1.07c) | 2.09 Gbps (1.56c) | 2.10 Gbps (1.07c) |
| ss2022 | 1.51 Gbps (1.01c) | 1.47 Gbps (1.15c) | 1.30 Gbps (1.01c) |
| trojan | 4.15 Gbps (1.03c) | 4.52 Gbps (1.68c) | 3.99 Gbps (1.03c) |
| anytls (sb server) | — | 3.02 Gbps (1.01c) | 3.12 Gbps (1.04c) |
| anytls (Go server) | — | 4.46 Gbps (1.57c) | 3.54 Gbps (1.16c) |
| cold connect | 6–85 ms | 6–8 ms | 1–6 ms |
| RSS | 61–65 MB | 51–52 MB | 14–16 MB |

Takeaways: honk has the lowest CPU per Gbps everywhere, ~4x less memory,
and the fastest cold connects. Remaining gaps: hy2 −8% vs both, ss2022
−12% vs dae, trojan −12% vs sing-box, anytls-vs-Go-server −21% vs
sing-box (see `doc/benchmark.*.md` history for the ss2022 codec rewrite
that closed most of its gap).

The sing-box engine runs inside the client netns with a TUN inbound
(`sb-client.json`, outbounds bound to `veth-client` so its own dials
escape the tun); honk/dae run on the root namespace as before.

### Post-inline changes (2026-07-29, honk dev)

Three data-path changes landed after the three-way run: anytls inline
streams (`AnyTlsStream`, no per-stream relay task/duplex), the ss
`poll_read` fast path (decrypt straight into the caller's buffer), and
TLS batch reads (`BatchRead`: BoringSSL returns one ~16 KiB record per
`SSL_read`; the wrapper drains the inner stream until the relay buffer
is full or pends).

Honest re-measurement so far (engine CPU checked non-zero to prove the
proxy path):

| Protocol | sing-box | honk before | honk after |
| --- | --- | --- | --- |
| trojan (TLS BatchRead) | 4.52 Gbps (1.68c) | 3.99 Gbps (1.03c) | **4.45 Gbps (~1.0c)** |

trojan is now within 2% of sing-box at ~60% of its CPU.

Note: an earlier version of this section listed ss2022 1.45 / anytls
3.14 / 4.37 Gbps. Those runs were discarded — a stale sing-box TUN
client was still holding the lab netns policy routes, so they measured
sing-box, not honk. ss2022/anytls re-measurement is pending a lab
server outage on .70.

### Cold first-connect latency (ms, health checks off, 3 runs)

| Protocol | dae | honk | note |
| --- | --- | --- | --- |
| hy2 | 10–11 | ~5 | |
| tuic | 84–86 | ~4 | was ~160 before the auth-grace removal |
| ss2022 | 6–7 | 6–27 | |
| trojan | 10–13 | 9–11 | |
| anytls | — | 9–12 | |

### Resources (steady state)

| Metric | dae | honk |
| --- | --- | --- |
| RSS | 61–65 MB | 14–16 MB |
| CPU during iperf (single core) | 1.0–1.4 cores | 1.0–1.2 cores |

### P0 flood acceptance (100k random 5-tuples, 20k/s)

| Phase | RSS | FDs |
| --- | --- | --- |
| baseline | 19 MB | 72 |
| flood peak | 365 MB (bounded) | 8 258 (bounded) |
| 60s after stop | 31 MB (back to baseline) | 70 |

## Production notes (10.10.10.1 gateway, nexi AnyTLS subscription)

- TCP (google/baidu/cloudflare) and HTTP/3 (cloudflare) pass after each
  deploy; gateway logs clean.
- HTTP/3 stall bursts (first bytes fast, body pauses ~14s) appear in
  multi-minute waves tied to the subscription's UDP line quality, not to
  engine builds — A/B deploys of beta.20/21/22 flip both ways within the
  same hour. Client qlog shows ~12% of datagrams declared-lost-then-late
  (latency artifact, not kernel/socket drops). Mitigation work (framed
  transports, UoT direct path, endpoint lifecycle kills) shipped in
  beta.17–beta.19; the residual artifact tracks WAN conditions.

## Regression gates

- `just outbound-ci` — fmt, clippy, honk-config + honk-outbound suites.
- `just clash-ci` — fmt, clippy, clash_api_test + integration_test.
- `just dns-ci` — DNS subsystem gate.
- Release CI (`.github/workflows/release.yml`) — workspace test gate +
  four-target build (x86_64/aarch64 × gnu/musl) + BTF check + tarballs.
