# Lab benchmark harness

`lab-bench.sh` is the single A/B benchmark harness for honk vs dae on the
lab (see `doc/benchmark.en.md` for the topology and the latest results).
It replaces the old `bench.sh` / `bench-cold.sh` / `bench-cpu.sh` /
`bench-honest.sh` script set.

## What it measures

Per engine × protocol:

- **cold** — first-request latency on a freshly restarted engine (3 runs,
  median; health checks are set to 3600s in both lab configs so they don't
  race the measurement)
- **hot p50/p95** — open-stream latency over 15 requests (proxy session
  already warm)
- **bw** — iperf3 `-R` download, 3 runs, median receiver bitrate
- **cpu** — engine CPU cores during the median bandwidth run
  (`/proc/<pid>/stat` utime+stime delta over wall time)
- **rss** — engine RSS after the bandwidth runs
- **direct baseline** — unproxied path through the engine datapath
  (`8080` http, `5300` iperf3)

dae has no AnyTLS support; `anytls-*` rows are skipped for it.

## Usage

The script runs **on the engine host** (10.10.10.57):

```bash
scp bench/lab-bench.sh root@10.10.10.57:/root/
ssh root@10.10.10.57 "bash /root/lab-bench.sh 'honk dae' 'hy2 tuic ss2022 trojan anytls-sb anytls-go'"
# args: [engines] [protocols] — both are space lists inside one arg
```

Stdout is a markdown table; raw TSV appends to `/root/bench-results.tsv`.

## Requirements on the lab

- Client netns `lab` with the veth pair + NAT (see the doc); both engine
  configs route by destination port (`5201/8001 → hy2` … `5206/8006 →
  anytls-go`, node server ports `direct(must)`, everything else direct).
- honk's lab config must expose the clash API on `127.0.0.1:9090` — the
  harness uses the API listener to identify the *active* engine process
  (a second honk instance parked on the singleton flock reports zero CPU
  and would poison the metrics).
- Targets on 10.10.10.70: http servers `8001-8006` + `8080`, iperf3
  servers `5201-5206` + `5300` (direct baseline), UDP echo `:53530`.

## Known measurement traps

- The lab is shared. Another session restarting engines mid-run corrupts
  numbers — re-run any row that looks off before publishing.
- Historical (fixed): single-stream iperf3 through AnyTLS read 2–3 Mbps
  because honk killed streams instantly on a full demux queue. Fixed by
  bounded HOL backpressure; single-stream anytls numbers are now valid
  and included in the table.

## sing-box as a third engine

`lab-bench.sh sing-box '<protos>'` runs sing-box 1.13.14 as a TUN client
**inside** the lab netns (`bench/sb-client.json` → `/root/sb-client.json`,
binary at `/root/sing-box`): client traffic hits the TUN, per-port route
rules pick the outbound, outbounds bind `veth-client`. Because no gateway
engine is running, the host must plain-forward lab traffic — the harness
assumes an idempotent masquerade (`/root/setup-nat.sh`, table `labnat`,
saddr 192.168.222.0/24 oif ens3). After each sing-box run the netns is
rebuilt (its TUN auto_route rewrites the routing table).
