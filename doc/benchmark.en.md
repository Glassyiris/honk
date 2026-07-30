# Benchmark Lab and Results

This document describes the reproducible benchmark environment for honk, the
measurement methodology, and the most recent results against
[dae](https://github.com/daeuniverse/dae) (same-time A/B). It lives in the
repo so the setup and the numbers stay in sync with the code.

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
└─────────────────────────────┘         │   http       :8001-8006,8080│
                                        │   iperf3     :5201-5206,5300│
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
  NAT): **~9.4 Gbps**.
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
scp bench/lab-bench.sh root@10.10.10.50:/root/
ssh root@10.10.10.50 "bash /root/lab-bench.sh 'honk dae' 'hy2 tuic ss2022 trojan anytls-sb anytls-go'"

# Protocol correctness matrix (TCP target / UDP echo / internet per protocol)
ssh root@10.10.10.50 bash /root/test-protocols.sh
```

## Results (2026-07-30, honk dev post-session-phases vs dae)

Same-time A/B on the lab; full methodology above. Latencies in seconds
(curl `time_total`), bandwidth is the iperf3 receiver median, CPU in cores,
RSS after the run.

| engine | protocol | cold | hot p50 | hot p95 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0051 | – | – | 9397 | 0.25 | 14 |
| honk | hy2 | 0.0082 | 0.0042 | 0.0055 | 1918 | 0.95 | 16 |
| honk | tuic | 0.0109 | 0.0033 | 0.0041 | 2073 | 1.04 | 15 |
| honk | ss2022 | 0.0043 | 0.0041 | 0.0049 | 1314 | 1.01 | 15 |
| honk | trojan | 0.0051 | 0.0025 | 0.0104 | 4427 | 1.03 | 14 |
| honk | anytls-sb | 0.0059 | 0.0021 | 0.0029 | see note¹ | 0.00 | 14 |
| honk | anytls-go | 0.0086 | 0.0023 | 0.0026 | see note¹ | 0.00 | 14 |
| dae | direct | 0.0055 | – | – | 9410 | 0.00 | 46 |
| dae | hy2 | 0.0061 | 0.0016 | 0.0021 | 3058 | 1.67 | 65 |
| dae | tuic | 0.0808 | 0.0786 | 0.0793 | 3335 | 1.70 | 63 |
| dae | ss2022 | 0.0073 | 0.0022 | 0.0029 | 1511 | 1.01 | 52 |
| dae | trojan | 0.0103 | 0.0082 | 0.0105 | 4178 | 1.03 | 54 |

The dae rows were re-run once to confirm: every number reproduced within
variance except trojan bandwidth, whose first reading (654 Mbps at
0.16 cores) was polluted by another test session restarting engines on the
shared lab mid-run. See "Known lab limits".

¹ **AnyTLS single-stream iperf3 anomaly (lab artifact, not an engine
regression)**: single-stream iperf3 through AnyTLS reads 2–3 Mbps in this
lab. The cause is on the server host — iperf3-daemon ↔ anytls-server
loopback delivery (iperf3 goes app-limited and stops feeding data). It
reproduces with a sing-box client over the same servers, while curl,
python and parallel streams all run at line rate. Measured with
`iperf3 -P 8`: **anytls-sb 4754 Mbps, anytls-go 3554 Mbps**.

### Reading the table

- **Bandwidth**: honk leads trojan (4427 vs 4178, +6%) and trails on the
  QUIC protocols (hy2 1918 vs 3058, tuic 2073 vs 3335 — congestion-control
  and window tuning remain open work); ss2022 is close (1314 vs 1511).
- **Latency**: the extreme case is TUIC: 3.3 ms hot vs dae's 78.6 ms —
  honk's BoringSSL QUIC backend resumes TLS 1.3 sessions from a
  process-wide ticket cache, so a warm TUIC dial is one RTT; dae pays a
  full QUIC handshake per connection. Cold TUIC tells the same story
  (10.9 vs 80.8 ms). Other rows are within a few ms both ways (ms-level
  noise on shared infrastructure).
- **CPU**: honk holds ~1 core at multi-Gbps on every protocol; dae needs
  1.7 cores on the QUIC protocols.
- **Memory**: honk idles ~3–4× leaner (14–16 MB vs 46–65 MB RSS).

### Earlier results

The 2026-07-29 runs (honk beta.22/beta.23, including the three-way with
sing-box 1.13.14 and the post-inline re-measurement at dev@1715d86) are
superseded by the table above. Numbers that carried over unchanged: honk's
~1-core CPU profile, the 4× memory advantage, and the trojan/tuic wins
over sing-box. The ss2022 codec rewrite (0.87 → 1.33 Gbps single-stream)
is in the 1314 Mbps figure above.

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
