# DNS listener pass (2026-10-30)

Client-visible DNS service comparison for the `2026-10-30` campaign.

- `dnsload.rs` — closed-loop UDP DNS load client. Build: `rustc -O dnsload.rs -o dnsload`.
- `dns-listener-bench.sh` — runs honk, dae and sing-box one at a time and appends to `results.tsv`.
- `dns-answer.py` — one-shot reply validator; every engine run must return the fixture's `192.0.2.42`.
- `honk-dns.dae` / `dae-dns.dae` — `dns.bind` on `192.168.222.1:15353`, upstream `udp://10.10.10.70:53539`.
- `sb-dns.json` — sing-box TUN with `{"port": 53, "action": "hijack-dns"}`; the client targets `1.1.1.1:53`.
- `results.tsv` — `cache` (one qname) and `unique` (fresh qname per query) at 1 and 8 threads, 15 s per cell.
- `answer-check.txt`, `*.log` — reply validation and engine logs.

Numbers are published in `doc/benchmark.en.md` / `doc/benchmark.zh.md` under the 2026-10-30 results.
