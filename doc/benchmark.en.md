# Benchmark Lab and Results

This document describes the reproducible benchmark environment for honk, the
measurement methodology, and the most recent results against
[dae](https://github.com/daeuniverse/dae) (same-time A/B). It lives in the
repo so the setup and the numbers stay in sync with the code.

## Lab topology

```text
┌─────────────────────────────┐         ┌─────────────────────────────┐
│ 10.10.10.57 (VM, 4C/2G; was .50 before the host-CPU rebuild)     │         │ 10.10.10.70 (physical, 50G) │
│                             │         │                             │
│  ┌───────────────┐          │  LAN    │  Protocol servers:          │
│  │ netns "lab"   │ veth     ├────────►│   hy2        :8443/udp      │
│  │ 192.168.222.2 ├──────────┤         │   tuic       :2444/udp      │
│  └───────┬───────┘          │         │   anytls-sb  :2445/tcp      │
│          │ NAT + TPROXY     │         │   anytls-go  :2443/tcp      │
│  honk / dae (one at a time) │         │   ss-2022    :2447/tcp      │
│  lan_ifname: veth-lab       │         │   trojan     :2446/tcp      │
│  wan_ifname: ens3           │         │  Targets:                   │
└─────────────────────────────┘         │   http       :8001-8006,8080│
                                        │   iperf3     :5201-5206,5300│
                                        │   udp echo   :53530         │
                                        └─────────────────────────────┘
```

- **Engine host (10.10.10.57)**: runs either honk or dae (never both). The
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
  NAT): **~9.4 Gbps**.
- **Engine VM CPU is host-passthrough (i5-13600K, AES-NI + AVX2)**. It
  used to be qemu64 with no SIMD — all QUIC crypto was software (honk's
  BoringSSL fell back to its `nohw` C ChaCha20-Poly1305, 34% of engine
  CPU), and QUIC bandwidth capped ~2–2.4 Gbps for both engines. With
  AES-NI the numbers below are crypto-representative of production
  hardware.
- Run-to-run variance on shared infrastructure is ±5%; stall-type artifacts
  on WAN subscriptions fluctuate on multi-minute windows and are not engine
  regressions — see "Production notes" below.
- The lab is shared with other test work. If a row looks off, re-run it
  before publishing (an engine restarted mid-run by someone else corrupts
  measurements).

## What's running where

| Component | Binary | Config |
| --- | --- | --- |
| hy2 server | official `hysteria` | `:8443`, password `testpass123`, cert CN `hy2.test` |
| TUIC server | `tuic-server` 1.0.0 | `:2444`, uuid `00000000-0000-0000-0000-000000000001` / `testpass123`, requires SNI `hy2.test` |
| AnyTLS server | sing-box | `:2445`, password `testpass123` |
| AnyTLS server | Go reference `anytls-server` | `:2443`, `-p testpass123` |
| SS 2022 server | sing-box | `:2447`, `2022-blake3-aes-128-gcm`, psk `8JCsHssyVTFyPy5lYdNhZg==` |
| Trojan server | sing-box | `:2446`, password `testpass123`, SNI `hy2.test` |
| Targets | python http.server, iperf3 | ports `8001-8006` + `8080` (direct), `5201-5206` + `5300` (direct); UDP echo `:53530` |

Engine configs route by destination port so no API switching is needed:
`5201/8001 → hy2`, `5202/8002 → tuic`, `5203/8003 → ss2022`,
`5204/8004 → trojan`, `5205/8005 → anytls-sb`, `5206/8006 → anytls-go`
(honk only — dae has no AnyTLS). Node server ports are `direct(must)`,
everything else falls back to direct.

## Methodology

One harness — `bench/lab-bench.sh` (in this repo, run on the engine host) —
replaces the old bench.sh/bench-cold.sh/bench-cpu.sh/bench-honest.sh set.
See `bench/README.md` for usage and lab requirements.

Per engine × protocol:

- **cold** — first-request latency on a freshly restarted engine, 3 runs,
  median. Health checks are at 3600s in both lab configs so the first probe
  doesn't race the measurement.
- **hot p50/p95** — open-stream latency over 15 requests against the
  per-protocol HTTP target (proxy session already warm). For QUIC protocols
  this is dominated by connection/session reuse; for mux protocols by the
  pooled session.
- **bw** — iperf3 `-R` download, single stream, 3 runs, median receiver
  bitrate.
- **cpu** — engine CPU cores during the median bandwidth run
  (`/proc/<pid>/stat` utime+stime delta over wall time). The honk pid is
  anchored on the clash-API listener so a second instance parked on the
  singleton flock (zero CPU) can't poison the metric.
- **rss** — engine RSS after the bandwidth runs.
- **direct baseline** — same measurements on the unproxied path
  (`8080`/`5300`).

```bash
scp bench/lab-bench.sh root@10.10.10.57:/root/
ssh root@10.10.10.57 "bash /root/lab-bench.sh 'honk dae' 'hy2 tuic ss2022 trojan anytls-sb anytls-go'"

# Protocol correctness matrix (TCP target / UDP echo / internet per protocol)
ssh root@10.10.10.57 bash /root/test-protocols.sh
```

## Results (2026-07-30, honk dev post-session-phases vs dae kdae, AES-NI)

Same-time A/B on the lab (engine VM with host-passthrough CPU; see "Known
lab limits" for the earlier software-crypto era). Latencies in seconds
(curl `time_total`), bandwidth is the iperf3 receiver median, CPU in
cores, RSS after the run. honk runs the musl release binary (mimalloc).

| engine | protocol | cold | hot p50 | hot p95 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0052 | – | – | 9413 | 0.16 | 53 |
| honk | hy2 | 0.0058 | 0.0018 | 0.0032 | 5239 | 1.06 | 64 |
| honk | tuic | 0.0024 | 0.0038 | 0.0049 | 5351 | 1.06 | 66 |
| honk | ss2022 | 0.0038 | 0.0018 | 0.0025 | 9388 | 0.37 | 57 |
| honk | trojan | 0.0053 | 0.0014 | 0.0055 | 9366 | 0.42 | 49 |
| honk | anytls-sb | 0.0052 | 0.0020 | 0.0031 | 4954¹ | – | 58 |
| honk | anytls-go | 0.0126 | 0.0035 | 0.0046 | 9272¹ | – | 55 |
| dae | direct | broken² | – | – | – | – | – |
| dae | hy2 | 0.0109 | 0.0030 | 0.0043 | 2996 | 0.75 | 62 |
| dae | tuic | 0.0852 | 0.0797 | 0.0809 | 3920 | 0.84 | 64 |
| dae | ss2022 | 0.0063 | 0.0040 | 0.0042 | 9396 | 0.49 | 52 |
| dae | trojan | 0.0093 | 0.0084 | 0.0107 | 9370 | 0.66 | 57 |
| dae | anytls-sb | 0.0088 | 0.0014 | 0.0023 | 9155 | 0.60 | 58 |
| dae | anytls-go | 0.0044 | 0.0017 | 0.0021 | 9379 | 0.62 | 59 |
| sing-box | direct | 0.0044 | – | – | 9410 | 0.41 | 47 |
| sing-box | hy2 | 0.0143 | 0.0014 | 0.0018 | 2930 | 0.88 | 52 |
| sing-box | tuic | 0.0102 | 0.0029 | 0.0048 | 2808 | 0.86 | 50 |
| sing-box | ss2022 | 0.0042 | 0.0040 | 0.0056 | 9390 | 1.19 | 49 |
| sing-box | trojan | 0.0112 | 0.0068 | 0.0104 | 9368 | 0.78 | 47 |
| sing-box | anytls-sb | 0.0113 | 0.0035 | 0.0041 | 5996 | 0.59 | 49 |
| sing-box | anytls-go | 0.0129 | 0.0023 | 0.0028 | 9252 | 0.95 | 46 |

The dae rows are the **kdae branch build** (`2a007b39`,
`unstable-20260729.r987`), built from `../dae` on the bench host — the
first dae build with AnyTLS support. The sing-box rows are **1.13.14**
running as a TUN client *inside* the lab netns (`bench/sb-client.json`
deployed to the engine host; per-port route rules mirror the engine
configs, outbounds bound to `veth-client`).

¹ honk's anytls rows carry a history: single-stream iperf3 used to read
2–3 Mbps here. The cause was honk's own — a full per-stream demux queue
(64 frames) triggered an *instant* stream kill, which fired 22 ms into a
single-stream run when the server's initial flight outran the fresh
relay task; the server then flooded the pooled session with PSH frames
for the dead sid. Fixed by real bounded HOL backpressure (the demux
parks up to 5 s on a full queue before killing). anytls-go now matches
dae; anytls-sb trails (the sing-box server emits patterns dae tolerates
better — future work).

² dae's direct path is broken on this lab kernel (kdae build): direct
flows time out while proxied flows work. All dae protocol rows above are
valid; there is no dae direct baseline.

### Reading the table

- **Bandwidth**: honk leads or ties everywhere. hy2 5239 (+75% vs dae,
  +79% vs sing-box), tuic 5351 (+36% / +90%), trojan and ss2022 at line
  rate with dae and sing-box, anytls-go 9272 (three-way tie). The one
  remaining gap is anytls against the sing-box server: honk 4954 vs dae
  9155 / sing-box 5996. ss2022 got to line rate via the BoringSSL AEAD
  swap: RustCrypto's aes-gcm measured 0.4–0.5 GB/s (AES-NI path not
  engaged) vs BoringSSL's 3.3–6.7 GB/s (`benches/ss_aead.rs`), and the
  swap took the row from 5339 Mbps / 1.01 cores to 9388 / 0.37 — now
  also ahead of dae on CPU (0.37 vs 0.49).
- **CPU per Gbps**: honk is the most efficient engine on every line-rate
  row — trojan 0.42 cores (dae 0.66, sing-box 0.78), ss2022 0.37 (dae
  0.49, sing-box 1.19). QUIC protocols cost honk ~1.06 cores at
  5.2+ Gbps; dae/sing-box need 0.75–0.88 for 2.8–3.9 Gbps.
- **Latency**: TUIC remains the extreme case — 3.8 ms hot vs dae's 79.7 ms
  (honk resumes TLS 1.3 sessions from a process-wide ticket cache; dae
  pays a full QUIC handshake per connection; cold tells the same story,
  2.4 vs 85.2 ms). Other rows are within a few ms both ways.
- **Memory**: honk's musl build uses mimalloc, which retains freed arenas
  — RSS 49–66 MB, at parity with dae (52–64 MB). The trade is deliberate:
  mimalloc buys ~+50% QUIC throughput over musl's stock malloc (5096 vs
  3037 Mbps A/B) for ~40 MB of retained memory.

### Earlier results (software-crypto lab, pre-AES-NI)

Before the engine VM got a host-passthrough CPU, QUIC numbers were
software-crypto-bound for both engines: honk hy2/tuic 2289/2383 Mbps vs
dae(kdae) 2511/2669, with honk's BoringSSL stuck on `nohw` C ChaCha20
(34% of engine CPU). Those rows are superseded by the table above. The
QUIC socket-buffer fix (8 MiB SO_RCVBUF/SO_SNDBUF + rmem_max/wmem_max at
16 MiB) and the 8/32 MiB receive-window defaults predate both tables and
apply to both.

## DNS micro-benchmarks (criterion)

`cargo bench -p honk-core --bench dns` — loopback, no external network.
Latest run (2026-07-30, x86_64):

| benchmark | mean |
| --- | --- |
| endpoint parse (udp/dot/doh/doq/h3) | 70–97 ns |
| cache get (hit) | 60 ns |
| cache put | 133 ns |
| cache mixed 90% read / 10% write | 32 ns |
| routing match (per-query rule eval) | 29–79 ns |
| force/restore txid | 1.4 ns |
| build A query | 114 ns |
| forwarder resolve (cache hit) | 283 ns |
| TCP pool exchange (reused conn) | 18 µs |
| UDP upstream exchange | 19 µs |
| length-prefixed framing (duplex) | 6 µs |

Per-query total (routing + cache-hit) is well under 1 µs; upstream
exchanges are loopback-RTT-bound as expected. The bench suite lives in
`crates/honk-core/benches/dns.rs`; mock servers run nodelay — without it
Nagle + delayed-ACK adds ~40 ms per TCP exchange and the numbers measure
the OS, not the code.

`cargo bench -p honk-outbound --bench ss_aead` compares AEAD backends on
Shadowsocks-sized chunks (RustCrypto aes-gcm 0.4–0.5 GB/s vs BoringSSL
AeadCtx 3.3–6.7 GB/s on AES-NI hardware — the reason the SS data path
uses BoringSSL).

## Production notes (10.10.10.1 gateway)

- TCP (google/baidu/cloudflare) and HTTP/3 (cloudflare) pass after each
  deploy; gateway logs clean.
- HTTP/3 stall bursts (first bytes fast, body pauses ~14s) appear in
  multi-minute waves tied to the subscription's UDP line quality, not to
  engine builds — A/B deploys of consecutive builds flip both ways within
  the same hour. Client qlog shows ~12% of datagrams declared-lost-then-late
  (latency artifact, not kernel/socket drops).
- 60-min canaries after each deploy sample FDs / established / CLOSE-WAIT /
  warn-rate; the Ready-pool metrics (`/stats` → `pool`: hits, misses,
  entries) are checked on the same cadence.

## Regression gates

- `just outbound-ci` — fmt, clippy, honk-config + honk-outbound suites.
- `just clash-ci` — fmt, clippy, clash_api_test + integration_test.
- `just dns-ci` — DNS subsystem gate.
- `cargo bench -p honk-core --bench dns` — DNS micro-benchmarks (above).
- Release CI (`.github/workflows/release.yml`) — workspace test gate +
  four-target build (x86_64/aarch64 × gnu/musl) + BTF check + tarballs.
