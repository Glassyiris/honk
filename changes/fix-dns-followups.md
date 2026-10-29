Changed

- Negative cache-hit outcome expiry uses the stored deadline, excluding preferred-family waits without reconstructing the deadline from a rounded TTL. Wire TTLs and routing behavior are unchanged.
- Clash `/stats.dns` reports DNS socket admission refusals and timeouts, proxy admission timeouts, and idle resources selected for pressure retirement, without per-query warnings.
- Tests that replace the process-global bootstrap resolver run in an isolated child process.
- The lint gates compile the DNS benchmarks.
