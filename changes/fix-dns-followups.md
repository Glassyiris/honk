Changed

- Negative cache-hit outcome expiry metadata no longer includes time spent waiting for a preferred-family sibling query. Wire TTLs and routing behavior are unchanged.
- Clash `/stats.dns` reports DNS socket admission refusals and timeouts, proxy admission timeouts, and idle resources selected for pressure retirement, without per-query warnings.
- Tests that replace the process-global bootstrap resolver run in an isolated child process.
- The lint gates compile the DNS benchmarks.
