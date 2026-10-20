# AnyTLS hot-path verification

No production code was changed. This directory records a differential profile
of honk's AnyTLS path against its own Trojan path, plus a correction to the
dae AnyTLS CPU cells in the main campaign.

## Correction: dae AnyTLS CPU denominator

`lab-bench.sh` divides process CPU ticks by the wall time of the whole
`iperf3` command. dae's AnyTLS command remains open for about 10 seconds after
the 8-second transfer, while honk's returns at about 8.0 seconds. The dae
AnyTLS-SB/AnyTLS-Go CPU cells (0.44/0.42 cores) therefore use an ~18-second
denominator. The raw TSV is unchanged; the 8-second transfer-window values in
`cpu-correction.tsv` put dae at ~1.01/0.96 cores and honk at ~0.85/0.84 cores.
The same effect applies to the historical `.70` dae AnyTLS CPU cells.

## Differential profile

A debug-info twin of commit `5d29dba6` was built with the same
`just build-musl 'ebpf,native-api,clash-api,mimalloc,rprx'` flags plus
`CARGO_PROFILE_RELEASE_DEBUG=1` and no stripping. Its `.text` layout differs
from the shipped stripped binary, so use it for relative attribution only.
`profile-case.py` starts the engine, warms one iperf3 flow, records
`/proc/<pid>/stat`, `/proc/<pid>/io`, per-thread CPU, and runs `perf record -a
-e cpu-clock -F 499 -g --call-graph dwarf,8192` during an 8-second iperf3 run.

| Case | Mbps | user cores | sys cores | total cores | iperf command |
| --- | ---: | ---: | ---: | ---: | ---: |
| honk AnyTLS-SB download | 20056 | 0.367 | 0.480 | 0.847 | 8.044 s |
| honk AnyTLS-SB upload | 17835 | 0.354 | 0.486 | 0.840 | 8.051 s |
| honk Trojan download | 24219 | 0.287 | 0.496 | 0.783 | 8.047 s |
| honk Trojan upload | 18801 | 0.214 | 0.363 | 0.577 | 8.048 s |
| dae AnyTLS-SB download | 19679 | 0.446* | 0.561* | 1.007* | 18.017 s |
| dae AnyTLS-Go download | 18098 | 0.437* | 0.526* | 0.963* | 18.010 s |

`*` scaled from the 18-second command window to the 8-second transfer. A
9-second `perf stat` task-clock window independently gives dae 9.505 CPU-s
(~1.06 cores) and honk 8.316 CPU-s (~0.92 cores).

## Top self samples (system-wide CPU-clock profile)

| Case | AES-GCM | `memcpy` | AnyTLS demux | malloc | mpsc push |
| --- | ---: | ---: | ---: | ---: | ---: |
| AnyTLS-SB download | 3.97% | 2.52% | 0.13% | 0.11% | 0.04% |
| Trojan download | 4.44% | 1.12% | — | — | — |
| AnyTLS-SB upload | 3.80% | 3.84% | — | — | — |
| Trojan upload | 4.14% | <0.1% | — | — | — |

AES-GCM is essentially the same; `memcpy` is 2.25x Trojan on download and
dominant on upload. The demux, mpsc and per-frame allocation are small. Kernel
stacks are generic TCP/TLS copies (`tcp_recvmsg` → `_copy_to_iter`;
`tcp_sendmsg` → `_copy_from_iter`) and are present for Trojan too, so system
time is not the AnyTLS-specific delta.

The candidate source sites are the inbound `read_frame_body` allocation plus
`AnyTlsStream::poll_read` copy (`crates/honk-outbound/src/proxy/anytls/mod.rs:1837`,
`.../inbound.rs:672`) and the upload `poll_write` copy plus writer
`encode_into` copy (`.../mod.rs:1612`, writer batching). This is a
profile-backed candidate, not an implemented fix.

## Limits

- One run per case; the lab is same-host and CPU-bound.
- Hardware PMU events are unavailable in the VM; the profile uses the
  `cpu-clock` software event.
- Percentages are shares of all system-wide samples, not honk-only CPU.
- Raw `perf.data` files (76–81 MB each) remain on the engine host at
  `/root/bench-20261020/prof/`; they are not committed.
