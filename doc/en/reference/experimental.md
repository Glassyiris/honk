# Experimental Configuration Reference

This reference describes the three supported nested sections under `experimental { ... }`.

## Section overview

| Nested section | Purpose |
| --- | --- |
| `clash_api` | Clash-compatible HTTP API and external dashboard |
| `cache_file` | SQLite persistence for runtime choices, mode, delay samples, and optional DNS state |
| `udp_nfqueue` | Held-first-packet decision path for ambiguous LAN-forwarded UDP |

At the nested-section level, the dae parser whitelists exactly `clash_api`, `cache_file`, and `udp_nfqueue`; no other section name is accepted under `experimental`.

## `clash_api`

| Field | Default | Meaning |
| --- | --- | --- |
| `external_controller` | `""` | HTTP listen address. An empty value disables the API server. |
| `external_ui` | `""` | External dashboard directory. An empty value disables dashboard serving and download. |
| `secret` | `""` | API authentication secret. An empty value disables authentication. |
| `default_mode` | `"Rule"` | Startup mode: `Rule`, `Global`, or `Direct`. A valid cached mode takes precedence. |

All `clash_api` fields are startup-owned. SIGHUP rejects a candidate configuration that changes any of them.

### Authentication and transport

With a non-empty `secret`, API requests use `Authorization: Bearer <secret>`; WebSocket upgrades may instead pass `?token=<secret>`. Static `/ui` content is outside this authentication middleware. The built-in listener serves plain HTTP and provides no TLS. Bind it to a loopback address such as `127.0.0.1`, or put an authenticated TLS reverse proxy in front of it; do not expose it directly on an untrusted network. See the [Clash API reference](./api.md) for the endpoint inventory.

### External UI

An absolute `external_ui` path is used literally. A relative path selects an existing directory below `global.data_dir` first, then an existing working-directory-relative directory; if neither exists, honk creates the target below `global.data_dir`. A missing or empty target triggers a background dashboard zip download. `HONK_UI_DOWNLOAD_URL` overrides the zip URL.

The download follows the normal traffic routing decision and resolves the selected group or node. A `block` decision aborts the download; it does not bypass policy.

### Startup mode

`default_mode` accepts the canonical modes `Rule`, `Global`, and `Direct`. When `cache_file` is enabled and contains a valid cached Clash mode, that value is restored instead. Invalid cached or configured values fall back to `Rule`.

## `cache_file`

| Field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Open the SQLite cache and enable runtime-state persistence. |
| `path` | `"cache.db"` | Database path. An absolute path is literal. For a relative path, an existing file below `global.data_dir` wins, then an existing legacy path relative to the original config directory; a new file is created below `global.data_dir`. |
| `cache_id` | `""` | Namespace for every database key. A non-empty value prefixes keys with `<cache_id>:`. |
| `store_fakeip` | `false` | FakeIP persistence intent only. The `fakeip:` prefix and flush API exist, but the engine does not populate or restore mappings yet. |
| `store_dns` | `false` | Persist and restore DNS cache answers using the exact-key v2 format. |

The whole `cache_file` section is startup-owned. SIGHUP rejects a candidate configuration that changes any field.

### Always-persisted state

Whenever `enabled` successfully opens the database, honk persists Selector choices, the Clash mode, and each node's last real delay sample independently of `store_fakeip` and `store_dns`. Delay samples are snapshotted every minute; restoration discards malformed, zero, or older-than-24-hour samples. Liveness is not restored.

### DNS persistence

With `store_dns: true`, entries use the `dns:v2:` key namespace and an `HDNS` version-2 binary payload. The v2 namespace is rollback-safe: a pre-v2 binary reads the legacy `dns:` namespace while excluding `dns:v2:` rows, so it leaves v2 data untouched.

A v2 row is restored only while unexpired and only when its key digest, canonical query wire, response wire identity, and active DNS policy match. The exact key also preserves the ingress profile, request scope, and operation, preventing reuse across different DNS contexts.

## `udp_nfqueue`

| Field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Enable NFQUEUE staging for ambiguous LAN-forwarded UDP decisions. |

`enabled` is the only accepted setting. There are no queue-number, worker, bypass, fanout, or fail-open knobs. Changing it requires a process restart; SIGHUP rejects the candidate configuration. Startup with `enabled: true` requires a build with the `ebpf` feature and the real eBPF backend. A build without `ebpf` or a run using `--mock-ebpf` is rejected.

### Traffic scope

The path stages only ambiguous LAN-forwarded UDP first packets, after LAN TC and before conntrack/NAT. Host-originated WAN egress remains on the TPROXY path; DNS port 53, internal or special traffic, reverse traffic, `must` and `block` results, and already-safe direct decisions are not queued. See the [NFQUEUE design](../design/nfqueue.md) for the mechanism and terminal transitions.

### Ownership and lifecycle

honk exclusively owns NFQUEUE queue `320` and the nftables objects `inet honk_nfqueue` / `udp_decision`. Firewall managers in the same network namespace must not create, replace, flush, or delete those objects while honk runs. Ordinary restart and cleanup preserve the pinned `UDP_DECISION_SEQUENCE` allocator so decision tokens are not reused.

### Corrupt-pin recovery

The allocator pin is `<bpf-pin-root>/UDP_DECISION_SEQUENCE`, normally `/sys/fs/bpf/UDP_DECISION_SEQUENCE`. Never remove it while a process can stage packets or token-bound state may still be live. To recover a corrupt or incompatible pin:

1. Keep NFQUEUE staging fenced; do not admit new staged flows.
2. Stop every honk process using that network namespace and pin root.
3. Verify queue `320` has no listener and the token-bound maps `CONN_STATE_MAP`, `ROUTING_HANDOFF_MAP`, `REDIRECT_TRACK`, and `UDP_DECISION_RETIRE_FENCE` are gone. If any remain, do not remove the allocator pin.
4. Remove only `UDP_DECISION_SEQUENCE`, once.
5. Restart honk and let it create a fresh allocator.

## Example

```dae
experimental {
    clash_api {
        external_controller: '127.0.0.1:9090'
        external_ui: 'zashboard'
        secret: 'replace-me'
        default_mode: Rule
    }
    cache_file {
        enabled: true
        path: 'cache.db'
        cache_id: 'gateway-main'
        store_fakeip: false
        store_dns: true
    }
    udp_nfqueue {
        enabled: true
    }
}
```

## Related docs

- [Clash API reference](./api.md)
- [NFQUEUE design](../design/nfqueue.md)
- [Global configuration reference](./global.md)
