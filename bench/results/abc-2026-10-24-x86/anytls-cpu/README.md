# AnyTLS CPU denominator correction (2026-10-24)

The first full-protocol pass divided process CPU by the whole `iperf3`
command wall. dae's AnyTLS client keeps that command alive for 18.02 s while
the transfer lasts 8.00 s, so its published 0.21/0.24 cores were CPU over
dead wall time: an artifact, not a cheaper engine.

`probe.py` samples `/proc/<pid>/stat` every 50 ms around one reverse run and
integrates the tick delta over the transfer window reported by iperf3
(`start.timestamp.timesecs` through `end.sum_received.seconds`). The raw
samples are in `probe/`; the engines and configs are the campaign's.

| Engine | Route | Command wall | Cores over command | Cores over transfer |
| --- | --- | ---: | ---: | ---: |
| honk | anytls-sb (5205) | 8.05–8.10 s | 0.404–0.406 | 0.403–0.408 |
| honk | anytls-go (5206) | 8.05–8.09 s | 0.425–0.437 | 0.431–0.437 |
| dae | anytls-sb (5205) | 18.02 s | 0.210–0.228 | **0.471–0.509** |
| dae | anytls-go (5206) | 18.02 s | 0.218–0.224 | **0.489–0.501** |
| dae | hy2 (5201) | 8.01 s | 0.602–0.624 | 0.604–0.623 |
| sing-box | anytls-sb (5205) | 8.01–8.02 s | 0.751 | 0.733–0.749 |
| sing-box | anytls-go (5206) | 8.01 s | 0.838–0.928 | 0.835–0.933 |

Only dae's AnyTLS rows diverge; every other protocol's client returned
within 0.02 s of its transfer, so its whole-command denominator is valid.

`lab-bench-cpu-window.sh` is the driver that produced `results.tsv` and
`stability.tsv` here (sha256 `56f27644dbb202bccd2057dc041b2a198040d50b3a38887c0beb8737af01baad`).
It now uses the run JSON's transfer duration whenever the command outlives it
by more than one second, for both the TCP and UDP arms; ordinary rows keep
their command denominator, so their published cells do not move. The campaign
itself ran with the older driver (`dbce07cf…`); its `results.tsv` still holds
the uncorrected AnyTLS CPU cells, superseded by this directory.

Re-measured rows (3 bandwidth runs, 15 hot requests, 200 loaded opens):

| Route | honk | dae | sing-box |
| --- | --- | --- | --- |
| anytls-sb | 0.41 cores, 9402 Mbps, 57 MiB | 0.50 cores, 9387 Mbps, 61 MiB | 0.75 cores, 9387 Mbps, 96 MiB |
| anytls-go | 0.43 cores, 9394 Mbps, 60 MiB | 0.54 cores, 9370 Mbps, 63 MiB | 0.86 cores, 9382 Mbps, 96 MiB |
| anytls-sb/udp | 0.55 cores, 1546 Mbps (77.2%) | 0.65 cores, 1616 Mbps (76.1%) | 1.16 cores, 1385 Mbps (78.6%) |
| anytls-go/udp | 0.58 cores, 1722 Mbps (74.8%) | 0.71 cores, 1772 Mbps (73.8%) | 1.17 cores, 1388 Mbps (78.9%) |
