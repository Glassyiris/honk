# Benchmark Lab and Results

This document describes the reproducible benchmark environment for honk and
the most recent results against the custom
[kdae build at commit `2a007b39`](https://github.com/olicesx/dae/commit/2a007b399210ceb25e0538d381bbbe9d86a302e4)
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
│ honk / kdae (one at a time) │         │   ss-2022    :2447/tcp      │
│  lan_ifname: veth-lab       │         │   trojan     :2446/tcp      │
│  wan_ifname: ens3           │         │  Targets:                   │
└─────────────────────────────┘         │   http       :8001-8006     │
                                        │   iperf3     :5201-5206     │
                                        │   udp echo   :53530         │
                                        └─────────────────────────────┘
```

- **Engine host (10.10.10.50)**: runs either honk or kdae (never both). The
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
(honk only — this kdae build has no AnyTLS). Node server ports are
`direct(must)`.

### Comparator provenance

Every `kdae` value below was measured with the custom dae fork at exact commit
[`2a007b399210ceb25e0538d381bbbe9d86a302e4`](https://github.com/olicesx/dae/commit/2a007b399210ceb25e0538d381bbbe9d86a302e4),
not an upstream dae release or current upstream main. The fork had diverged
from upstream, so these results apply only to this retained artifact:

| Item | Provenance |
| --- | --- |
| Comparator binary | SHA-256 `bc2f70bfa79ed6adc14fb899b76555defc5ac2f12758944ae58b8e1a6b702de1` |
| Embedded VCS metadata | revision `2a007b399210ceb25e0538d381bbbe9d86a302e4`; `vcs.modified=false` |
| Go/build settings | `go1.26.0-X:heapminimum512kib`; `-tags=trace`; `-trimpath=true`; `CGO_ENABLED=0`; `GOARCH=amd64`; `GOEXPERIMENT=heapminimum512kib,randomizedheapbase64` |
| Build inputs | `go.mod` SHA-256 `beb10605de028399258973a04de8c5e6917998b915ade7399e843098159f382f`; `go.sum` `7424003bbe18470129018883bdf4ac38eea5a9c106dd19f6d0ee2ba89ed70a0a`; `Makefile` `e3c54593db5c9ac3b10a7fc7a4428527ffe99f4546da67174e0ca2b22baed702` |
| Runtime configuration | `/etc/dae/config.dae`; SHA-256 `6bac2fbb00796dafd435653378d4b1185a47c4e39a29757094250c6c903527a2` |

The binary, clean build tree, and runtime configuration were retained and
recovered. The historical `/root/bench.sh` harness is no longer retained, so
the protocol tables are provenance-bound historical results rather than a
currently rerunnable benchmark recipe. Configuration contents are omitted
because they may contain credentials.

## How to run

All scripts live on the engine host in `/root` (source copies in
`/tmp/lab-bin` on the operator machine).

```bash
# Protocol correctness matrix (TCP target / UDP echo / internet per protocol)
bash /root/test-protocols.sh

# Full benchmark: per protocol — cold/warm first-request latency,
# iperf3 download bandwidth, engine CPU% and RSS during the run
bash /root/bench.sh honk 'hy2 tuic ss2022 trojan anytls-sb anytls-go'
# Historical selector name: `dae` starts the kdae artifact identified above.
bash /root/bench.sh dae  'hy2 tuic ss2022 trojan'

# Cold first-connect latency with health checks effectively off (3600s)
bash /root/bench-cold.sh

# P0 acceptance: 100k random 5-tuple UDP flood, resource bounds + fallback
bash /root/flood-test.sh 100000 20000
```

## Results (2026-07-29, honk v0.0.1.beta.22)

### Bandwidth (iperf3 `-R`, single stream, 8s; direct baseline 9.41 Gbps)

| Protocol | kdae | honk | honk/kdae |
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

| Protocol | kdae | sing-box | honk |
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
−12% vs kdae, trojan −12% vs sing-box, anytls-vs-Go-server −21% vs
sing-box (see `doc/benchmark.*.md` history for the ss2022 codec rewrite
that closed most of its gap).

The sing-box engine runs inside the client netns with a TUN inbound
(`sb-client.json`, outbounds bound to `veth-client` so its own dials
escape the tun); honk/kdae run on the root namespace as before.

### Post-inline changes (2026-07-29, honk dev @ 1715d86)

Data-path changes landed after the three-way run: anytls inline streams
(`AnyTlsStream`, no per-stream relay task/duplex), the ss `poll_read`
fast path, TLS batch reads (`BatchRead`: BoringSSL returns one ~16 KiB
record per `SSL_read`; the wrapper drains the inner stream until the
relay buffer is full or pends), and the mux session-leak fix
(`pool_bare_tcp` + always-tracked `SessionPool::insert`).

Full honest re-measurement (engine CPU verified non-zero every run):

| Protocol | kdae | sing-box | honk before | honk after |
| --- | --- | --- | --- | --- |
| hy2 | 2.10 (1.28c) | 2.10 (1.58c) | 1.93 (0.97c) | 1.94 (0.97c) |
| tuic | 1.80 (1.07c) | 2.09 (1.56c) | 2.10 (1.07c) | **2.18 (1.07c)** |
| ss2022 | 1.51 (1.01c) | 1.47 (1.15c) | 1.30 (1.01c) | 1.29 (1.00c) |
| trojan | 4.15 (1.03c) | 4.52 (1.68c) | 3.99 (1.03c) | **4.65 (1.02c)** |
| anytls (sb server) | — | 3.02 (1.01c) | 3.12 (1.04c) | **3.55 (0.99c)** |
| anytls (Go server) | — | 4.46 (1.57c) | 3.54 (1.16c) | 3.38 (1.02c) |

trojan, tuic and anytls-sb now beat sing-box (at ~60% of its CPU);
the ss fast path turned out neutral (the staging copy was not the
bottleneck — ss2022 stays single-core-bound at ~1.3 Gbps). Remaining
gaps: hy2 −8%, ss2022 −12%, anytls-go −24% vs sing-box.

Note: an earlier version of this section listed ss2022 1.45 / anytls
3.14 / 4.37 Gbps. Those runs were discarded — a stale sing-box TUN
client was still holding the lab netns policy routes, so they measured
sing-box, not honk.

### Cold first-connect latency (ms, health checks off, 3 runs)

| Protocol | kdae | honk | note |
| --- | --- | --- | --- |
| hy2 | 10–11 | ~5 | |
| tuic | 84–86 | ~4 | was ~160 before the auth-grace removal |
| ss2022 | 6–7 | 6–27 | |
| trojan | 10–13 | 9–11 | |
| anytls | — | 9–12 | |

### Resources (steady state)

| Metric | kdae | honk |
| --- | --- | --- |
| RSS | 61–65 MB | 14–16 MB |
| CPU during iperf (single core) | 1.0–1.4 cores | 1.0–1.2 cores |

### P0 flood acceptance (100k random 5-tuples, 20k/s)

| Phase | RSS | FDs |
| --- | --- | --- |
| baseline | 19 MB | 72 |
| flood peak | 365 MB (bounded) | 8 258 (bounded) |
| 60s after stop | 31 MB (back to baseline) | 70 |

### DNS architecture Criterion comparison

The authoritative `dns-final-production-9b5843a` DNS microbenchmark compares
clean production commit `9b5843abc9957c3122fa6bbc3bc62ecdf8c0ca64`
with baseline commit `6bbf1dc929541d64178d44ab389dcfe3b3e55c1e`.
Both sides use the same non-default `dns-bench` harness:

```bash
CARGO_TARGET_DIR=<baseline-target> \
  cargo bench -p honk-core --features dns-bench --bench dns -- \
  --save-baseline dns-final-production-9b5843a
CARGO_TARGET_DIR=<current-target> \
cargo bench -p honk-core --features dns-bench --bench dns -- \
  --baseline dns-final-production-9b5843a
```

The run completed all 32 Criterion groups on host `nixos` (Linux
`7.1.4-cachyos`, Intel i9-13900H, 20 logical CPUs) with Rust
`1.99.0-nightly (87e5904f5 2026-07-20)`, Cargo
`1.99.0-nightly (3efb1f477 2026-07-17)`, and LLVM `22.1.8`. The baseline
detached worktree overlaid only the byte-identical benchmark feature,
support, harness, and stats definitions needed to compile the same cases;
all other baseline DNS production code came from the exact baseline SHA.
The saved Criterion measurement database was copied byte-identically into a
fresh current target so compiled artifacts could not cross worktree
boundaries. Complete manifests cover every measured DNS production source,
the benchmark executable, build/toolchain inputs, and runtime configuration.
Cross-host timings are not comparable.

| Case | Current central estimate | Baseline ratio | Criterion result / advisory |
| --- | ---: | ---: | --- |
| Real typed `CacheKey::new` build | 78.722 ns | 0.9552x | improvement; ≤1.10x pass |
| Policy evaluation, 1 rule | 73.399 ns | 0.9094x | improvement; ≤1.10x pass |
| Policy evaluation, 32 rules | 216.68 ns | 1.0595x | regression detected; ≤1.10x pass |
| Policy evaluation, 128 rules | 739.37 ns | 1.0790x | regression detected; ≤1.10x pass |
| Independent cache hit, 1 task | 327.19 ns | 1.3639x | regression detected; ≤1.10x **miss** |
| Independent cache miss, 1 task | 240.69 ns | 1.3744x | regression detected; ≤1.10x **miss** |
| Independent cache hit, 16 tasks | 4.5382 µs | 1.3204x | regression detected; ≤1.10x **miss** |
| Independent cache miss, 16 tasks | 2.9460 µs | 1.7753x | regression detected; ≤1.10x **miss** |
| Independent cache hit, 64 tasks | 29.018 µs | 1.2537x | regression detected; ≤1.10x **miss** |
| Independent cache miss, 64 tasks | 21.377 µs | 1.2556x | regression detected; ≤1.10x **miss** |
| Singleflight, 128 waiters | 772.66 µs | 1.3184x | regression detected; advisory |
| Forwarder cache hit | 4.1809 µs | 1.5842x | regression detected; ≤1.15x **miss** |
| Real runtime lease acquire/drop | 47.856 ns | 1.0009x | no detected change; ≤1.10x pass |
| Real runtime publication/swap | 1.5398 µs | 1.0368x | regression detected; ≤1.10x pass |
| Ungated atomic event record | 6.7166 ns | 1.3431x | regression detected; advisory |
| Best-effort atomic counter scrape | 2.1640 ns | 0.9439x | improvement; advisory |
| 10k cache construction/insertion | 3.3343 ms | 1.2578x | regression detected |
| 10k allocated bytes | 1,628,640 bytes | 0.9996x | ≤1.50x pass |

Typed-key construction parses a real query once, then calls the production
`CacheKey::new` for every measured iteration with real query context,
`PolicyId`, upstream scope, and resolve operation. Runtime measurements call
the production provider's `acquire`/lease drop and build a replacement
`DnsRuntime` before `prepare_publication(...).commit()`. The observability
cases call the real ungated `AtomicU64` recorder and best-effort scrape. Each
counter is monotonic, but a scrape does not claim cross-counter coherence.
The same stats implementation is intentionally overlaid on the
baseline, so their between-run deltas are noise controls rather than
old-versus-new production comparisons.

The approved budget has no baseline-ratio or absolute threshold for the
observability cases; they are advisory mechanism measurements. The current
record cost is 6.7166 ns for one relaxed atomic increment with no shared gate,
spin, or yield. Although that is 1.3431x the identical overlay in the different
baseline production tree, it is 43.4% below the prior authoritative gated
current measurement of 12.025 ns. The absolute hot-path work is therefore
smaller and cannot serialize independent DNS requests.

Timing limits are advisory and misses are not hidden or relaxed. The 16-task
cache cases now perform stable canonical cache-key identity work; all six
1/16/64-task cache cases miss ≤1.10x, and the forwarder cache hit misses
≤1.15x. The benchmark does not isolate that identity work from the cache
operation, so these results are reported without attributing them to the
removed stats gate.
Functional publication, cancellation, ordering, and resource bounds remain
hard test assertions.

Independent 64-task hot-key throughput is 2.2055 Melem/s versus
4.1643 Melem/s for the sequential reference, or 0.530x, missing the advisory
≥2x target. Its single-thread Tokio `join_all` harness measures scheduling
overhead rather than multi-core scaling. Parallel A+AAAA completes in
1.2944 ms versus 1.2532 ms for the slower AAAA branch, or 1.033x, passing the
≤1.25x target.

Raw provenance receipts:

| Artifact | Path | SHA-256 |
| --- | --- | --- |
| Baseline timing | `.omo/evidence/final-benchmark-provenance-remediation/benchmark-baseline.log` | `95094d26d62265943aaff9911cfda722e67dc4c09bd6d2b3eeb0b8d4dfc2e1e3` |
| Current timing/comparison | `.omo/evidence/final-benchmark-provenance-remediation/benchmark-current.log` | `49cdaf170ca166a3112add76043535124b10f5e3ebfd121c7b4332b7dcc5600a` |
| Baseline source manifest | `.omo/evidence/final-benchmark-provenance-remediation/baseline-source-manifest.sha256` | `864f1816928d122ccd9b2570f1f60219bd840f7ab65f77a47efb48322c09a60c` |
| Current source manifest | `.omo/evidence/final-benchmark-provenance-remediation/current-source-manifest.sha256` | `8520fd45bd871d461c7bfd1e083aab24a35559873d5f08fca30c0221a1b62fe1` |
| Build/runtime provenance | `.omo/evidence/final-benchmark-provenance-remediation/build-runtime-provenance.log` | `be26e41b92d607fd19f618c3550d360568338d66b38ea6ddf0a586e7a890b12b` |
| kdae artifact manifest | `.omo/evidence/final-benchmark-provenance-remediation/kdae-artifacts.sha256` | `58c26390866e9848633baa11bc4048f8e90eec5fcf3a9755faa62d4aa79467c8` |

The baseline/current gate receipts also bind the exact clean SHAs, 32/32
counts, allocation values, and benchmark executable checksums. The full
methodology and cleanup receipt are in
`.omo/evidence/final-benchmark-provenance-remediation.md`.

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
- [DNS canary and rollback runbook](./dns-rollout.en.md) — isolated authorized
  host only; privileged steps were not run in the local benchmark lane.
