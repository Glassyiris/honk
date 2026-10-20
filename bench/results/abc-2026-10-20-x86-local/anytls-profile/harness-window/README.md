# Temporary transfer-window CPU validation

This directory records a temporary harness change: `bandwidth()` and
`udp_bandwidth()` use `iperf3`'s reported `end.sum_received.seconds` as the CPU
denominator instead of the whole command's wall time. `window-cpu.patch` is the
diff against `bench/lab-bench.sh`; it was applied only to a copy on the lab
host and is not part of the repository.

## Targeted A/B/C

Three engines, Trojan + both AnyTLS routes; cold=1, hot=2, TCP median of 3,
UDP one run. The direct controls are omitted from this summary: sing-box's
direct row read 83 Gbps / 0.00 cores in this run, i.e. it bypassed the TUN, so
it is not a valid direct comparison. Proxy rows were still proxied.

| Engine | Route | Mbps | corrected CPU cores |
| --- | --- | ---: | ---: |
| honk | anytls-sb | 20019 | 0.86 |
| honk | anytls-go | 19290 | 0.87 |
| honk | trojan | 23299 | 0.79 |
| dae | anytls-sb | 19407 | 0.97 |
| dae | anytls-go | 17848 | 0.95 |
| dae | trojan | 16064 | 0.67 |
| sing-box | anytls-sb | 19162 | 1.35 |
| sing-box | anytls-go | 17900 | 1.42 |
| sing-box | trojan | 18087 | 1.42 |

Dae AnyTLS UDP also corrects from the raw 0.23/0.26 to 0.53/0.60 cores; honk
is 0.47/0.54. This confirms that both dae AnyTLS TCP and UDP CPU cells in the
main campaign used an ~18-second denominator.

## `opt-level=3` twin

A temporary release-profile `opt-level=3` build (same features, `strip=true`)
was A/B'd against the measured `opt-s` binary on AnyTLS-SB.

| Direction | opt-s median | opt3 median | Delta |
| --- | ---: | ---: | ---: |
| download | 20941 Mbps / 0.839 cores | 21121 Mbps / 0.847 cores | +0.9% throughput / +0.9% CPU |
| upload | 18408 Mbps / 0.839 cores | 18171 Mbps / 0.833 cores | −1.3% throughput / −0.7% CPU |

The change is within run-to-run noise and does not justify a codegen profile
change.

## Limits

- Temporary, uncommitted harness and build changes; no production code changed.
- One targeted campaign, not a replacement for the main A/B/C results.
- `opt3` has two upload runs; its delta is not statistically established.
- The fixture was removed after the run (`cleanup.txt`).
