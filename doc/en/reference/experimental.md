# Experimental Configuration Reference

This reference describes the current nested sections under `experimental { ... }`.

## Section overview

| Nested section | Purpose |
| --- | --- |
| `clash_api` | Clash-compatible HTTP API and external dashboard |
| `cache_file` | SQLite persistence for runtime choices, mode, delay samples, and optional DNS state |
| `native_api` | Independent, opt-in read-only native API and local UI directory |

`udp_nfqueue { enabled: ... }` is a deprecated compatibility section. Dae and structured loaders accept it, print a migration warning, and copy its value to `global.nfqueue_enable`; new configurations should use the global field directly.

## `native_api`

Requires the default-off `native-api` Cargo feature; it does not require `clash-api`. Enabling it without that feature fails startup. All fields are restart-required: SIGHUP rejects changes and preserves the active listener and configuration generation. Unknown fields, nested scalar blocks, malformed booleans, and empty security-list members are errors.

| Field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Start the independent native listener. |
| `listen` | `"127.0.0.1:9527"` | Numeric IP plus port 1–65535; no hostname or `:port` shorthand. |
| `secret` | `""` | Bearer credential, independent of the Clash credential. Required unless explicit anonymous loopback is enabled. |
| `allow_anonymous_loopback` | `false` | Permit credential-free requests only when secret is empty and the actual listening IP is loopback. A configured secret always requires authentication. |
| `allow_origins` | empty list | Additional explicit HTTP(S) origins, without paths, credentials, query, fragment, `null`, or wildcards. |
| `allowed_hosts` | empty list | Additional explicit HTTP Host authorities, without URL schemes, paths, credentials, or wildcards. Omitted port means 80, not the listener's port. |
| `ui` | `""` | Empty disables hosting; otherwise a trusted local directory with readable `index.html`. No embedded UI or startup download/build. |
| `record_flows` | `true` | Retain bounded userspace decisions while native API is enabled, even without clients. `false` disables recording and releases its buffers; restart-required. |

```dae
experimental {
    native_api {
        enabled: true
        listen: '127.0.0.1:9527'
        secret: 'operator-supplied-random-token'
        allow_anonymous_loopback: false
        ui: '/usr/share/doona'
    }
}
```

Nonempty native secrets must be visible ASCII without whitespace or commas, matching the HTTP bearer parser; unsupported bytes fail shared configuration admission rather than creating an unusable listener.

Replace the example secret. For local credential-free development, omit `secret` and explicitly set `allow_anonymous_loopback: true`; never publish that anonymous listener through a reverse proxy. Plain HTTP with a token on a non-loopback network is not a secure deployment. Terminate TLS at a trusted proxy.

Default Host acceptance is the concrete listening authority; loopback also accepts `localhost`, `127.0.0.1`, and `[::1]` at that port. A wildcard bind does not authorize arbitrary Hosts. Only directly corresponding HTTP origins are automatically allowed. A TLS proxy preserving `Host: panel.example` needs `allowed_hosts: 'panel.example'` and `allow_origins: 'https://panel.example'`; if it preserves `Host: panel.example:443`, add `allowed_hosts: 'panel.example', 'panel.example:443'`. Forwarded headers do not grant authorization.

Lists use individually quoted comma-separated entries, such as `allow_origins: 'http://localhost:3000', 'https://panel.example'`. Omit a list to leave it empty; JSON brackets and a single aggregate-quoted list are not accepted.

Relative UI paths follow the existing dependency search: an existing path under `global.data_dir`, then `/var/share/honk`, then the working directory; a missing dependency resolves under `global.data_dir` and startup fails. The administrator owns the directory and any symlink targets. See the [native API contract](./api.md#native-api-m1).

## `clash_api`

| Field | Default | Meaning |
| --- | --- | --- |
| `external_controller` | `""` | HTTP listen address. An empty value disables the API server. |
| `external_ui` | `""` | External dashboard directory. An empty value disables dashboard serving and download. |
| `external_ui_download_url` | `""` | HTTP(S) dashboard ZIP URL. An empty value uses the built-in zashboard URL. |
| `external_ui_download_detour` | `""` | Node or group tag used for the download. An empty value follows normal traffic routing. |
| `secret` | `""` | API authentication secret. An empty value disables authentication. |
| `default_mode` | `"Rule"` | Startup mode: `Rule`, `Global`, or `Direct`. A valid cached mode takes precedence. |

All `clash_api` fields are startup-owned. SIGHUP rejects a candidate configuration that changes any of them.

### Authentication and transport

With a non-empty `secret`, API requests use `Authorization: Bearer <secret>`; WebSocket upgrades may instead pass `?token=<secret>`. Static `/ui` content is outside this authentication middleware. The built-in listener serves plain HTTP and provides no TLS. Bind it to a loopback address such as `127.0.0.1`, or put an authenticated TLS reverse proxy in front of it; do not expose it directly on an untrusted network. See the [Clash API reference](./api.md) for the endpoint inventory.

An explicitly enabled non-loopback bind with an empty secret emits `unsafe-api-bind` at `experimental.clash_api.external_controller`, including structured input. The diagnostic contains neither the endpoint nor the secret. Loopback sample configurations do not warn; this warning does not change bind, authentication, or CORS policy.

### External UI

An absolute `external_ui` path is used literally. A relative path selects an existing directory below `global.data_dir` first, then an existing directory below `/var/share/honk`, then an existing working-directory-relative directory; if none exists, honk creates the target below `global.data_dir`. A missing or empty target triggers a background dashboard ZIP download. A non-empty `external_ui_download_url` replaces the built-in zashboard URL; `HONK_UI_DOWNLOAD_URL` has highest precedence over both.

A non-empty `external_ui_download_detour` forces the initial request and every redirect through that node or group. `direct` downloads directly, `block` aborts, and a group resolves its authoritative leaf for each exchange. When the field is empty, each URL follows the normal traffic routing decision as before. An unavailable tag, download failure, or extraction failure is logged without stopping the engine.

### Startup mode

`default_mode` accepts the canonical modes `Rule`, `Global`, and `Direct`. When `cache_file` is enabled and contains a valid cached Clash mode, that value is restored instead. Invalid cached or configured values fall back to `Rule`.

## `cache_file`

| Field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Open the SQLite cache and enable runtime-state persistence. |
| `path` | `"cache.db"` | Database path. An absolute path is literal. For a relative path, an existing file below `global.data_dir` wins, then an existing file below `/var/share/honk`, then an existing path relative to the original config directory; a new file is created below `global.data_dir`. |
| `cache_id` | `""` | Namespace for every database key. A non-empty value prefixes keys with `<cache_id>:`. |
| `store_fakeip` | `false` | FakeIP persistence intent only. The `fakeip:` prefix and flush API exist, but the engine does not populate or restore mappings yet. |
| `store_dns` | `false` | Persist and restore DNS cache answers using the exact-key v2 format. |

The whole `cache_file` section is startup-owned. SIGHUP rejects a candidate configuration that changes any field.

### Always-persisted state

Whenever `enabled` successfully opens the database, honk persists Selector choices, the Clash mode, and each node's last real delay sample independently of `store_fakeip` and `store_dns`. Delay samples are snapshotted every minute; restoration discards malformed, zero, or older-than-24-hour samples. Liveness is not restored.

### DNS persistence

With `store_dns: true`, entries use the `dns:v2:` key namespace and an `HDNS` version-2 binary payload. The v2 namespace is rollback-safe: a pre-v2 binary reads the legacy `dns:` namespace while excluding `dns:v2:` rows, so it leaves v2 data untouched.

A v2 row is restored only while unexpired and only when its key digest, canonical query wire, response wire identity, and active DNS policy match. The exact key also preserves the ingress profile, request scope, and operation, preventing reuse across different DNS contexts.


## Example

```dae
experimental {
    clash_api {
        external_controller: '127.0.0.1:9090'
        external_ui: 'zashboard'
        external_ui_download_url: 'https://example.com/dashboard.zip'
        external_ui_download_detour: proxy
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
}
```

## Related docs

- [Clash API reference](./api.md)
- [NFQUEUE design](../design/nfqueue.md)
- [Global configuration reference](./global.md)
