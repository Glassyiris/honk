# Hot latency and tail variance analysis (2026-10-24)

Why this directory exists: the campaign's hot p50 and loaded p99 cells are
single-run values. Two repeats of the affected rows and two independent
probes below show that the small rankings flip; the campaign table keeps the
original values and the documentation qualifies them.

## Probes

- `hot-probe.sh PORT WARMUP SAMPLES` — per-request curl timings
  (`time_connect`, `time_starttransfer`, `time_total`) from netns `lab`.
- `seq-probe.sh PORT COUNT` — per-request totals with no warmup after a
  fresh engine start.
- `conn-count.py IFACE PORT SECONDS` — passive AF_PACKET counter for TCP
  SYNs without ACK and distinct UDP source ports (upstream session reuse).
- `hot-analysis.sh ENGINE` — orchestration for the steady probe.

## Steady-state hot latency (idle host, 5 warmups, 30 samples)

| Engine | Protocol | connect p50 | ttfb − connect p50 | total p50 |
| --- | --- | ---: | ---: | ---: |
| honk | tuic | 0.061 ms | 1.308 ms | 1.401 ms |
| honk | ss2022 | 0.065 ms | 1.370 ms | 1.499 ms |
| honk | trojan | 0.054 ms | 0.536 ms | 0.619 ms |
| honk | anytls-sb | 0.061 ms | 1.001 ms | 1.129 ms |
| honk | anytls-go | 0.057 ms | 0.938 ms | 1.025 ms |
| honk | hy2 | 0.086 ms | 1.381 ms | 1.508 ms |
| dae | tuic | 0.055 ms | 1.439 ms | 1.620 ms |
| dae | ss2022 | 0.061 ms | 1.576 ms | 1.722 ms |
| dae | trojan | 0.108 ms | 5.022 ms | 5.370 ms |
| dae | anytls-sb | 0.051 ms | 1.005 ms | 1.080 ms |
| dae | anytls-go | 0.056 ms | 0.940 ms | 1.021 ms |
| dae | hy2 | 0.053 ms | 1.343 ms | 1.462 ms |
| sing-box | tuic | 0.071 ms | 1.505 ms | 1.588 ms |
| sing-box | ss2022 | 0.069 ms | 1.611 ms | 1.708 ms |
| sing-box | trojan | 0.120 ms | 5.609 ms | 5.874 ms |
| sing-box | anytls-sb | 0.068 ms | 1.247 ms | 1.339 ms |
| sing-box | anytls-go | 0.060 ms | 1.212 ms | 1.283 ms |
| sing-box | hy2 | 0.067 ms | 1.294 ms | 1.415 ms |

The eBPF engines intercept the client SYN, so connect is ~0.06 ms; the whole
hot cost is one tunnel round trip plus relay. honk is within 0.05 ms of dae
on every route here and faster on TUIC/SS2022.

## Fresh-engine sequence and upstream reuse (AnyTLS-Go, 20 requests)

| Engine | First request | Requests 2–20 (range) | Upstream SYNs |
| --- | ---: | --- | ---: |
| honk | 2.35 ms | 0.99–2.24 ms | 1 |
| dae | 7.14 ms | 1.04–5.05 ms | 2 |

One upstream AnyTLS session served the whole sequence on both engines, so
the campaign gap is not session churn. dae pays a larger first-request
session setup (7.1 ms) than honk (2.35 ms).

## Repeats of the harness rows

- `hot-check/` — AnyTLS-Go only: honk hot 1.179 ms / p99 13.06 ms,
  dae 1.500 ms / 15.58 ms (campaign: 1.950 / 17.63 vs 1.313 / 14.51).
- `hot-check2/` — TUIC, SS2022, AnyTLS-SB, AnyTLS-Go: hot p50 honk/dae
  1.624/1.812, 1.389/1.492, 1.362/1.346, 1.495/1.296; p99 2.60/2.39,
  13.64/16.31, 16.07/12.19, 15.62/20.50.

Both repeats use the same harness, binaries and fixture as the campaign.
See `doc/benchmark.en.md` / `doc/benchmark.zh.md` for the published table.
