# ARM A/B/C (NanoPi R2S `10.10.10.251`), 2026-10-31

CPU-bound companion to the 2026-10-30 x86 campaign.

- Host: NanoPi R2S, 4x Cortex-A53, 1 GiB RAM, 1 GbE `eth0`, kernel 6.12.94, OpenWrt (musl).
- Client: netns `lab` (192.168.222.2); server fixture: canonical `.70`.
- Engines: honk `v0.1.0-beta.3-95-g6d731c5a` (static aarch64 musl, merged bench branch),
  dae v2.1.1 (aarch64), sing-box v1.14.3 built from source as a static aarch64 binary
  (`-tags "with_quic with_gvisor"`; the official arm64 asset is glibc and cannot run on musl).
- `results-arm.tsv` / `stability-arm.tsv` — four-protocol pass (hy2 tuic ss2022 trojan).
- `dns-listener/` — DNS listener pass: honk/dae bind `127.0.0.1:15353` with a host-side client
  (the `daens` mounts displace the `lab` namespace mount on this host), sing-box answers via
  TUN with `{"port":53,"action":"hijack-dns"}`; `sing-box-rows.txt` preserves the first pass.
- Host prerequisites added for the fixture: `labnat` masquerade for `192.168.222.0/24` on
  `eth0`, an `inet fw4` forward accept for `veth-lab`→`eth0`, and per-interface forwarding.
- The campaign supplies an external holder process and `LAB_HOLDER_PID` so the harness
  reattaches `lab` after each engine start.

Numbers are published in `doc/benchmark.en.md` / `doc/benchmark.zh.md` under the 2026-10-31
ARM section.
