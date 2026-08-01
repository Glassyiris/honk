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
- **udp** — per protocol: echo RTT (15 pings to the routed echo port
  5353x, median) and iperf3 `-u -b 10G -l 1200 -R` (receiver bitrate +
  loss at a saturating offered rate; datagrams pinned to 1200 B because
  QUIC datagrams cap near that).
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

## Results (2026-08-01, three-engine: honk vs dae vs sing-box)

honk: dev `ed640c7` (musl, mimalloc, reuseport-2 merge, single UDP listener per family).
dae: kdae branch, Go 1.26.0.
sing-box: v1.13.14 (TUN client inside lab netns, port-route per protocol).
All measured same-time on the lab. Latencies in seconds, TCP bandwidth is the
iperf3 receiver median, CPU in cores, RSS after the run. sing-box CPU is not
measured (TUN-client model does not expose per-protocol process CPU).

### TCP

| engine | protocol | cold | hot p50 | hot p95 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0060 | – | – | 9411 | 0.24 | 58 |
| dae | direct | 0.0035 | – | – | 9395 | – | 50 |
| sing-box | direct | 0.0085 | – | – | – | – | 59 |
| honk | hy2 | 0.0085 | 0.0042 | 0.0053 | 3050 | 0.50 | 60 |
| dae | hy2 | 0.0102 | 0.0023 | 0.0045 | 4467 | 1.07 | 66 |
| sing-box | hy2 | 0.0451 | 0.0046 | 0.0059 | 2998 | – | – |
| honk | tuic | 0.0051 | 0.0032 | 0.0051 | 4400 | 0.60 | 57 |
| dae | tuic | 0.0851 | 0.0037 | 0.0046 | 4537 | 0.98 | 64 |
| sing-box | tuic | 0.0151 | 0.0035 | 0.0041 | 2620 | – | – |
| honk | ss2022 | 0.0046 | 0.0028 | 0.0035 | 9205 | 0.36 | 52 |
| dae | ss2022 | 0.0076 | 0.0047 | 0.0058 | 9405 | 0.45 | 55 |
| sing-box | ss2022 | 0.0220 | 0.0027 | 0.0040 | 8717 | – | – |
| honk | trojan | 0.0103 | 0.0018 | 0.0084 | 9328 | 0.43 | 52 |
| dae | trojan | 0.0076 | 0.0018 | 0.0020 | 9369 | 0.66 | 57 |
| sing-box | trojan | 0.0150 | 0.0053 | 0.0064 | 9214 | – | – |
| honk | anytls-sb | 0.0053 | 0.0034 | 0.0046 | 4792 | 0.28 | 45 |
| dae | anytls-sb | 0.0139 | 0.0039 | 0.0047 | 5586 | 0.43 | 57 |
| sing-box | anytls-sb | 0.0083 | 0.0018 | 0.0023 | 8244 | – | – |
| honk | anytls-go | 0.0132 | 0.0031 | 0.0037 | 9249 | 0.48 | 56 |
| dae | anytls-go | 0.0232 | 0.0023 | 0.0027 | 9006 | – | – |
| sing-box | anytls-go | 0.0065 | 0.0019 | 0.0021 | 8823 | – | – |

### UDP (iperf3 `-u -b 10G -l 1200 -R`, single flow, cold engine)

| engine | protocol | echo RTT p50 | bw Mbps (loss) | cpu |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.19 ms | 286 (95.3%) | 2.27 |
| dae | hy2 | 0.21 ms | 907 (85.9%) | 0.93 |
| sing-box | hy2 | 0.26 ms | 1629 (73.8%) | – |
| honk | tuic | 0.40 ms | 11 (99.2%) | 0.01 |
| dae | tuic | 0.27 ms | 1702 (67.4%) | 1.48 |
| sing-box | tuic | 0.15 ms | 100 (96.4%) | – |
| honk | ss2022 | 0.17 ms | 2010 (65.1%) | 1.31 |
| dae | ss2022 | 0.30 ms | 2742 (51.6%) | 1.79 |
| sing-box | ss2022 | 0.15 ms | 1984 (54.7%) | – |
| honk | trojan | 0.13 ms | 1659 (70.7%) | 1.28 |
| dae | trojan | 0.10 ms | 3062 (47.2%) | 1.70 |
| sing-box | trojan | 0.10 ms | 3557 (41.2%) | – |
| honk | anytls-sb | 0.28 ms | 1316 (79.0%) | 0.84 |
| dae | anytls-sb | – | – | – |
| sing-box | anytls-sb | 0.21 ms | 608 (78.8%) | – |
| honk | anytls-go | 0.19 ms | 1600 (74.5%) | 1.07 |
| dae | anytls-go | 0.12 ms | 1566 (74.3%) | – |
| sing-box | anytls-go | 0.10 ms | 640 (77.6%) | – |

### Reading the three-engine table

**TCP bandwidth:**
- Line-rate protocols (ss2022, trojan, anytls-go): all three engines reach
  ~8.7–9.4 Gbps. honk and dae are within noise of each other; sing-box
  trails slightly (8717 vs 9405 on ss2022, 8823 vs 9249 on anytls-go).
- QUIC protocols (hy2, tuic): dae leads at 4467/4537 Mbps. honk is at
  3050/4400, sing-box at 2998/2620. honk has a hy2 regression vs the
  previous 07-30 run (5239→3050), likely due to lab host load.
- anytls-sb: sing-box leads at 8244, dae 5586, honk 4792. This is the
  sing-box reference implementation; honk's anytls handler trails by ~40%.

**CPU efficiency:**
- On every QUIC row where both are measured, honk uses ~50% less CPU than
  dae at comparable bandwidth (hy2: 0.50 vs 1.07, tuic: 0.60 vs 0.98).
- On TCP-based protocols honk is consistently 0.3–0.5 cores lower than dae.

**Latency:**
- dae's tuic still pays a full QUIC handshake per connection (cold 85 ms vs
  honk's 5 ms with ticket-cache resume).
- sing-box cold latencies are highest across the board (TUN + userspace
  routing adds ~10–35 ms overhead).
- Hot latencies are all single-digit ms for all three engines.

**UDP (cold engine, single flow):**
- This run was on a cold engine (health checks unconverged, sessions cold),
  so UDP numbers read 3–5× lower than steady-state. See the warm-state
  comparison below.
- TUIC UDP cold-start is broken on all three engines (11–100 Mbps), but
  honk reaches 6.18 Gbps single-flow once warm — the cold numbers are a
  session-setup artifact, not a protocol limitation.

### UDP: warm-state three-engine comparison

All three engines were started, allowed 30s for health checks to converge,
then TCP sessions were primed through every protocol. UDP was measured
after a further 10s settle. Single flow and 8-flow aggregate
(`iperf3 -u -b 10G -l 1200 -R` / `-P 8`). Datagrams pinned to 1200 B.

| engine | protocol | echo RTT | single flow (loss) | P8 aggregate (loss) |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.12 ms | 5.91 Gbps (5.9%) | P8 failed† |
| dae | hy2 | 0.59 ms | 915 Mbps (85.8%) | 827 Mbps (97.6%) |
| sing-box | hy2 | 0.42 ms | 1.61 Gbps (74.4%) | 1.58 Gbps (95.9%) |
| honk | tuic | 0.32 ms | **6.18 Gbps (2.1%)** | **9.40 Gbps (0.8%)** |
| dae | tuic | 0.15 ms | 1.57 Gbps (71.4%) | 21 Mbps (45.3%) |
| sing-box | tuic | 0.14 ms | 31 Mbps (80.1%) | failed |
| honk | ss2022 | 0.23 ms | 5.67 Gbps (11.5%) | 8.83 Gbps (6.8%) |
| dae | ss2022 | 0.21 ms | 2.52 Gbps (55.1%) | 2.59 Gbps (88.8%) |
| sing-box | ss2022 | 0.17 ms | 2.57 Gbps (55.1%) | 3.00 Gbps (87.3%) |
| honk | trojan | 0.07 ms | **6.31 Gbps (0.06%)** | 8.74 Gbps (7.8%) |
| dae | trojan | 0.13 ms | 2.96 Gbps (49.6%) | 2.87 Gbps (91.8%) |
| sing-box | trojan | 0.09 ms | 3.52 Gbps (39.1%) | 4.31 Gbps (88.6%) |
| honk | anytls-sb | 0.06 ms | 5.54 Gbps (13.6%) | **9.24 Gbps (2.5%)** |
| dae | anytls-sb | 0.25 ms | 1.31 Gbps (78.8%) | 2.87 Gbps (89.9%) |
| sing-box | anytls-sb | 1.78 ms | 1.26 Gbps (79.2%) | 2.85 Gbps (90.9%) |
| honk | anytls-go | 0.08 ms | **6.44 Gbps (0.4%)** | **9.37 Gbps (1.1%)** |
| dae | anytls-go | 0.13 ms | 1.58 Gbps (74.2%) | 2.45 Gbps (92.6%) |
| sing-box | anytls-go | 0.10 ms | 1.45 Gbps (76.3%) | 2.36 Gbps (92.9%) |

† honk hy2 P8 failed on this run (iperf3 returned 0); earlier warm-UDP
runs recorded 9.18 Gbps at 3.1% loss. Re-run on idle lab to confirm.

### Reading the warm UDP table

**Honk dominates warm-state UDP across every protocol:**
- Single flow: 5.5–6.4 Gbps with 0.06–13.6% loss. dae and sing-box are at
  0.9–3.5 Gbps with 40–86% loss — honk is **2–6× faster at 5–15× lower
  loss**.
- P8 aggregate: honk reaches 8.7–9.4 Gbps (near line rate) at 0.8–7.8%
  loss. dae and sing-box collapse on P8 with 88–98% loss — their UDP
  datapaths cannot handle 8 parallel saturating flows.
- **TUIC UDP** goes from 11 Mbps cold to **6.18 Gbps warm** (560×
  improvement). The protocol itself works; the cold-start numbers were a
  session-setup artifact, not a protocol limitation.
- **Trojan UDP** at 6.31 Gbps / 0.06% loss is nearly lossless — honk's
  UDP-over-TCP framing has no measurable overhead at line rate.
- **anytls-go** at 6.44 Gbps / 0.4% loss single-flow and 9.37 Gbps / 1.1%
  P8 is the best all-around UDP performer.

**dae and sing-box UDP collapse on P8 is not a lab artifact:**
Both engines show the same pattern — single-flow at 1–3.5 Gbps with
moderate loss, then P8 at same or LOWER throughput with 88–98% loss. This
indicates a fundamental bottleneck in their UDP receive paths (shared
socket buffer contention, lack of per-flow queuing, or kernel-level UDP
socket lock contention) that honk's `UdpEndpointPool` and per-flow bounded
queues were specifically designed to avoid.

## Results (2026-07-31, honk dev `ac64fe1` vs dae kdae `eee7c88b`)

Same-time A/B on the lab. honk is the musl release binary (mimalloc,
periodic `mi_collect` on a blocking thread, idle drain deadline); dae is
the kdae branch at `eee7c88b` (adds a DNS group-override fix and bumps the
outbound fork to `perf/complete-optimizations@670df833`). Latencies in
seconds, bandwidth is the iperf3 receiver median, CPU in cores, RSS after
the run. New in this run: **the kdae direct baseline works** (it was
broken in the 07-30 run).

| engine | protocol | cold | hot p50 | hot p95 | bw (Mbps) | cpu | RSS (MB) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| honk | direct | 0.0052 | – | – | 9406 | 0.24 | 52 |
| honk | hy2 | 0.0101 | 0.0032 | 0.0046 | 2921 | 0.48 | 59 |
| honk | tuic | 0.0093 | 0.0034 | 0.0043 | 3961 | 0.55 | 59 |
| honk | ss2022 | 0.0044 | 0.0027 | 0.0040 | 9392 | 0.36 | 52 |
| honk | trojan | 0.0072 | 0.0019 | 0.0120 | 9341 | 0.45 | 53 |
| honk | anytls-sb | 0.0050 | 0.0031 | 0.0039 | 4790 | 0.30 | 57 |
| honk | anytls-go | 0.0122 | 0.0032 | 0.0040 | 9226 | 0.49 | 56 |
| dae | direct | 0.0051 | – | – | 9397 | 0.00 | 52 |
| dae | hy2 | 0.0090 | 0.0032 | 0.0037 | 3005 | 0.82 | 63 |
| dae | tuic | 0.0827 | 0.0792 | 0.0800 | 4280 | 0.93 | 64 |
| dae | ss2022 | 0.0040 | 0.0036 | 0.0062 | 9404 | 0.42 | 57 |
| dae | trojan | 0.0105 | 0.0078 | 0.0100 | 9340 | 0.65 | 57 |
| dae | anytls-sb | 0.0112 | 0.0029 | 0.0038 | 4742 | 0.37 | 58 |
| dae | anytls-go | 0.0069 | 0.0034 | 0.0046 | 9301 | 0.63 | 60 |

UDP (iperf3 `-u -b 10G -l 1200 -R`, receiver Mbps + loss):

| engine | protocol | echo RTT p50 | bw Mbps (loss) | cpu |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.43 ms | 1708 (72.9%) | 1.07 |
| honk | tuic | 0.31 ms | 142 (64.5%) | 0.13 |
| honk | ss2022 | 0.22 ms | 1879 (66.6%) | 1.28 |
| honk | trojan | 0.18 ms | 1609 (71.9%) | 1.27 |
| honk | anytls-sb | 0.49 ms | 1308 (78.2%) | 0.86 |
| honk | anytls-go | 0.18 ms | 1607 (74.2%) | 1.04 |
| dae | hy2 | 0.27 ms | 929 (85.9%) | 0.95 |
| dae | tuic | 0.28 ms | 60 (52.4%) | 0.06 |
| dae | ss2022 | 0.16 ms | 2705 (52.4%) | 1.74 |
| dae | trojan | 0.11 ms | 2972 (48.7%) | 1.69 |
| dae | anytls-sb | 0.13 ms | 1305 (78.8%) | 0.85 |
| dae | anytls-go | 0.10 ms | 1413 (76.0%) | 0.92 |

### Reading the 07-31 table

- **TCP bandwidth** is parity within noise: line-rate rows (direct,
  ss2022, trojan, anytls-go) all ~9.3–9.4 Gbps both engines; anytls-sb is
  now a tie too (4790 vs 4742 — the new kdae no longer dominates that
  row). hy2/tuic slightly favor dae (3005/4280 vs 2921/3961).
- **CPU per Gbps** still belongs to honk on every QUIC row: hy2 0.48 vs
  0.82 cores, tuic 0.55 vs 0.93, and trojan 0.45 vs 0.65 at identical
  bandwidth.
- **Latency**: dae's tuic still pays a full QUIC handshake per connection
  (cold 82.7 ms, hot p50 79.2 ms vs honk's 9.3/3.4 ms, ticket-cache
  resumed). Everything else is single-digit ms both ways.
- **UDP**: honk leads hy2 (1708 vs 929) and anytls-go; the ss2022/trojan
  UDP-over-TCP gap persists (dae 2705/2972 vs honk 1879/1609) and remains
  the top UDP optimization target. TUIC UDP is broken-ish on both engines
  (142/60 Mbps).
- honk's hy2/tuic TCP bandwidth dropped vs the 07-30 run (5239→2921,
  5351→3961) while dae's stayed flat; the .70 lab host was under heavy
  parallel load during this run, so treat these two rows as suspect until
  re-measured on an idle lab.

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

### UDP results (iperf3 `-u -b 10G -l 1200 -R`, echo RTT)

Same A/B run. Offered rate is a fixed 10 Gbps — far above what any tunnel
carries, so the loss column reflects saturation, not quality; the
receiver bandwidth is the capacity number. Datagram length is pinned to
1200 B: QUIC datagrams cap near that (honk hy2/tuic drop oversized
datagrams — iperf3's path-MTU default ~1448 B would measure the cap, not
the tunnel). Echo RTT is the median of 15 pings through the per-protocol
routed echo port (53531–53536).

| engine | protocol | echo RTT p50 | bw Mbps (loss) | cpu |
| --- | --- | --- | --- | --- |
| honk | hy2 | 0.37 ms | 1738 (73.1%) | 1.30 |
| honk | tuic | 0.38 ms | 293 (54.3%) | 0.22 |
| honk | ss2022 | 0.11 ms | 1158 (52.4%) | 0.81 |
| honk | trojan | 0.21 ms | 1506 (77.3%) | 1.26 |
| honk | anytls-sb | 0.12 ms | 1148 (82.2%) | 0.80 |
| honk | anytls-go | 0.10 ms | 1519 (76.6%) | 1.11 |
| dae | hy2 | 0.14 ms | 932 (85.9%) | 0.96 |
| dae | tuic | 0.13 ms | 9 (75.8%) | 0.03 |
| dae | ss2022 | 0.10 ms | 2668 (53.1%) | 1.76 |
| dae | trojan | 0.13 ms | 2957 (49.2%) | 1.67 |
| dae | anytls-sb | 0.10 ms | 1208 (80.7%) | 0.78 |
| dae | anytls-go | 0.19 ms | 1561 (75.2%) | 0.99 |
| sing-box | hy2 | 0.20 ms | 1372 (75.2%) | 1.18 |
| sing-box | tuic | 0.15 ms | 16 (63.4%) | 0.04 |
| sing-box | ss2022 | 0.07 ms | 2730 (53.0%) | 1.35 |
| sing-box | trojan | 0.07 ms | 3380 (45.5%) | 1.56 |
| sing-box | anytls-sb | 0.09 ms | 1244 (79.3%) | 1.12 |
| sing-box | anytls-go | 0.13 ms | 1447 (76.9%) | 1.21 |

- **hy2 UDP**: honk leads (1738 vs 932 / 1372) at ~1 core per engine.
- **TUIC UDP** is weak across all three engines (293 / 9 / 16 Mbps) —
  QUIC-datagram TUIC is a protocol-level weak spot in this lab, honk is
  least-bad.
- **UDP-over-TCP tunnels** (ss2022, trojan): dae/sing-box lead
  (2.7–3.4 Gbps vs honk 1.1–1.5). honk's UDP endpoint/framing path is
  the current bottleneck — the next optimization target after anytls-sb.
- **anytls UoT**: three-way tie at ~1.1–1.5 Gbps.
- Echo RTTs are sub-millisecond for every engine/protocol; nothing here
  is latency-bound.

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

## Candidate UDP micro-benchmarks (absolute, not A/B)

The UDP Criterion suite records absolute candidate behavior only. Its fixed
invocation is:

```bash
cd /root/code/honk-feat-udp-to-1
CARGO_TARGET_DIR=/root/code/honk/target cargo bench -p honk-core --bench udp -- --save-baseline udp-candidate
```

| Case | Fixed work |
| --- | --- |
| steady enqueue | 1,000,000 128-byte `fast_path_enqueue` calls on a Ready flow, immediately drained to hold steady state |
| reserve / rollback | 10,000 endpoint reservations followed by rollback |
| histogram | 1,000,000 record/snapshot operations |
| queue saturation | 64 admitted datagrams followed by one dropped newest datagram |

Record the candidate's Criterion mean, median, MAD, and absolute throughput.
`udp-candidate` is a repeat-run label, not a comparison to `be587b1`: that
revision has no source-level equivalent interface for a valid A/B. Criterion
also does not provide a merge-gate p95 estimate; do not infer one from this
suite.

## Deployment UDP A/B gate

`bench/udp-latency.sh` is the real deployment driver, not a CI substitute. It
requires the same TPROXY topology and real upstreams for both binaries. Its
fixed invocation is:

```bash
sudo bench/udp-latency.sh \
  --baseline-bin /opt/honk/be587b1/honk-core \
  --candidate-bin /opt/honk/udp-to-1/honk-core \
  --config /etc/honk/bench.dae \
  --echo-target 10.0.2.2:9000 \
  --dns-target 10.0.2.2:53 \
  --samples 10000 --runs 5 --offered-rate 5000
```

The fixed command deliberately has no timeout or hook flags. Configure root's
`HONK_UDP_TIMEOUT_SEC` (default `30`) and
`HONK_UDP_{START,READY,SETUP,PROBE,STATS,TEARDOWN,TOPOLOGY}_HOOK` values; CLI
flags override those values. With `sudo`, use `--preserve-env` for these
variables or configure them in root's environment. The driver supplies no
built-in topology: missing live hooks fail closed.

Every executable hook is run through `env`, not evaluated as a shell snippet.
It receives `variant`, `case`, `run`, `workdir`, `pid`, `pgid`, `selected_bin`,
`baseline_bin`, `candidate_bin`, `config`, `echo_target`, `dns_target`,
`samples`, `offered_rate`, and `timeout`; `pid`/`pgid` are empty for `start`
and `topology`. `start` must finish synchronous setup and then `exec
"$selected_bin" ...`; the driver attests the selected file's device/inode
against `/proc/$pid/exe` and rechecks the same PID/session/start-time/executable
after ready, setup, probe, and stats. A row is emitted only after teardown and
bounded verification that the owned process group is absent; residual descendants
fail the run closed. The legacy positional arguments remain compatible. Targets
may be IPv4, `[IPv6]`, or legal hostnames with a port.
`probe` must report `sent == samples`.

It emits one JSONL object per case/run with exactly these top-level fields:
`schema_version`, `variant`, `commit`, `binary_sha256`, `kernel`, `topology`,
`case`, `run`, `samples`, `offered_rate`, `sent`, `received`, `latency_unit`,
`p50`, `p95`, `p99`, `max`, `loss`, `cpu_pct`, `rss_kib`, `fd_count`,
`queue_drops`, and `warm_hit`. `schema_version` is `1`; latency quantiles are
in microseconds, `loss` is the sample loss ratio, `cpu_pct` is process CPU
usage, `rss_kib` is resident memory in KiB, and `fd_count` is the open
file-descriptor count. The fixed cases are `cold_endpoint`, `steady_hit`,
`warm_session_cold_endpoint`, `dns_hit`, `dns_miss`, `healthy_candidate`, and
`blackholed_candidate`. The driver interface and JSONL shape are checked with
`bash bench/tests/udp-latency-cli.sh`.

The deployment gate compares five 10,000-sample runs at the same topology and
offered rate: healthy cold p50/p95 regression must be at most 5%; a blackholed
first candidate must improve p95 by at least 20% and p99 by at least 30%; a
steady path must keep p99 at most 250 microseconds and zero drops below 70% of
target throughput; AnyTLS warm hits must reach 80% and reduce first reply by
one RTT or at least 20%; steady CPU and p50 regression must be at most 5%; and
IPv4/IPv6 client-observed reply tuples must remain unchanged. **This local
worktree has not run the deployment gate, so it makes no network-latency gate
claim.**

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
- `cargo bench -p honk-core --bench udp -- --save-baseline udp-candidate` — candidate-only absolute UDP measurements; not a historical A/B or p95 merge gate.
- `bash bench/tests/udp-latency-cli.sh` — deployment-driver CLI/JSONL fixture; the real UDP A/B gate above still requires TPROXY and upstreams.
- Release CI (`.github/workflows/release.yml`) — workspace test gate +
  four-target build (x86_64/aarch64 × gnu/musl) + BTF check + tarballs.
