Fixed

- The standalone `dns.bind` UDP listener handles much higher concurrent query load. Up to four supervisors, bounded by the Tokio worker count, receive datagrams in batches of up to eight, and an answer that is ready on its first poll is sent without spawning a task. A recent cache hit with an unchanged address set skips the route-projection locks for up to one second, so its route may expire up to one second later than the cache entry.
- Sockets owned by upstream DNS use one bounded budget that persists across reloads. Under pressure, idle transports are reclaimed and a busy direct UDP upstream spreads over up to four sockets per address. A query whose upstream cannot obtain a socket is answered with `SERVFAIL`.
- Concurrent UDP DNS client queries per DNS generation are capped at `min(1536, MemTotal / 4 / 256 KiB)`, replacing the previous cap of at most 256, with a fallback of 1536 when `MemTotal` is unreadable. Above the cap, `dns.bind` answers `REFUSED` and transparent port-53 UDP drops the query.
- The startup descriptor-budget log replaces `dns_slow` with `dns_sockets` and `dns_udp_queries`.
