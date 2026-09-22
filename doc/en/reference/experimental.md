# Experimental Configuration Reference

This reference describes the current nested sections under `experimental { ... }`.

## Section overview

| Nested section | Purpose |
| --- | --- |
| `clash_api` | Clash-compatible HTTP API and external dashboard |
| `cache_file` | SQLite persistence for runtime choices, mode, delay samples, and optional DNS state |
| `native_api` | Independent, opt-in observations, bounded diagnostics, runtime/source control and local UI directory |

`udp_nfqueue { enabled: ... }` is a deprecated compatibility section. Dae and structured loaders accept it, print a migration warning, and copy its value to `global.nfqueue_enable`; new configurations should use the global field directly.

## `native_api`

Requires the default-on `native-api` Cargo feature; it does not require `clash-api`, and the listener remains default-off. Enabling it without that feature fails startup. All effective fields are restart-required: SIGHUP rejects changes and preserves the active listener and configuration generation. Unknown fields, nested scalar blocks, malformed booleans, and empty security-list members are errors.

| Field | Default | Meaning |
| --- | --- | --- |
| `enabled` | `false` | Start the independent native listener. |
| `listen` | `"127.0.0.1:9527"` | Numeric IP plus port 1–65535; no hostname or `:port` shorthand. |
| `secret` | `""` | Static bearer credential, independent of the Clash credential. A nonempty value selects token mode and cannot be combined with `password_auth`. Listener secrets are masked by value in API responses; a value shorter than 8 bytes is not masked and is reported at startup. |
| `password_auth` | `false` | Select administrator password login when `secret` is empty. Cannot be combined with `allow_anonymous_loopback`. |
| `allow_anonymous_loopback` | `false` | Permit credential-free requests only when `secret` is empty, `password_auth` is false and the actual listening IP is loopback. |
| `allow_origins` | empty list | Additional explicit HTTP(S) origins, without paths, credentials, query, fragment, `null`, or wildcards. |
| `allowed_hosts` | empty list | Additional explicit HTTP Host authorities, without URL schemes, paths, credentials, or wildcards. Omitted port means 80, not the listener's port. |
| `ui` | `""` | Empty disables hosting; otherwise a trusted local directory with readable `index.html`, or `embedded` with the default-off `native-ui` feature. No startup download, extraction or frontend build. |
| `record_flows` | `true` | Permit bounded userspace flow recording under the API client-attachment rule or an explicit runtime pin. `false` prohibits recording, including runtime pins; configuration changes require restart. |
| `record_traffic` | `true` | Keep up to 600 traffic samples for 600 seconds, even without clients. `false` disables history and releases its buffer on restart; current counters remain available. |
| `record_memory` | `true` | Keep up to 600 memory samples for 600 seconds, even without clients. `false` disables history and releases its buffer on restart; current readings remain available. |
| `record_logs` | `true` | Permit up to 512 structured logs for 60 seconds under the API client-attachment rule or an explicit runtime pin. `false` prohibits capture; configuration changes require restart. Console/Clash logging remains independent. |
| `record_dns_log` | `true` | Permit completed client DNS history under the API client-attachment rule or an explicit runtime pin, bounded to 512 records and 8 MiB. `false` prohibits history; configuration changes require restart. |
| `probe_allowed_cidrs` | empty list | Explicit IP CIDRs authorizing otherwise restricted resolved probe targets and proxy-server addresses. Empty denies restricted addresses, including loopback/private/link-local ranges. |
| `probe_allowed_ports` | empty list | Additional ports 1–65535 for configured HTTP/DNS probe targets. Defaults permit HTTP 80, HTTPS 443 and DNS 53; raw TCP probes use only the node's configured server port. CIDR authorization remains independently required. |
| `config_content` | `false` | Accepted for compatibility and ignored. Every admitted request may read available sources; only listener-secret values are masked. |
| `config_write` | `false` | Allow whole-source replacement and reload for the accepted main file and all accepted includes, excluding listener-credential-bearing sources. Requires a nonempty `secret` or `password_auth`. |
| `writable_includes` | empty list | Accepted for compatibility and ignored; it grants no path authority and does not restrict accepted includes. |
| `geosite_download_url` | `""` | Final direct HTTP(S) source for updating the loaded geosite asset. Requires `config_write`; empty disables updates when geosite is loaded. |
| `geoip_download_url` | `""` | Final direct HTTP(S) source for updating the loaded geoip asset, with the same authorization and bounds. |

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

Authentication mode is restart-required. A nonempty `secret` selects the existing static-token mode. An empty `secret` with `password_auth: true` selects password mode. An empty `secret` with explicit anonymous loopback and an actual loopback bind selects the existing development mode. An enabled listener with none of these fails validation. Password mode requires an empty `secret` and is rejected with `allow_anonymous_loopback`; `config_write: true` likewise requires token or password mode.

Replace the example secret. For local credential-free development, omit `secret` and explicitly set `allow_anonymous_loopback: true`; never publish that anonymous listener through a reverse proxy. Plain HTTP with a token on a non-loopback network is not a secure deployment. Terminate TLS at a trusted proxy.

Default Host acceptance is the concrete listening authority; loopback also accepts `localhost`, `127.0.0.1`, and `[::1]` at that port. A wildcard bind accepts any IP-literal Host, and `localhost`, at the listening port, since those name the listener itself on whichever interface the request arrived; DNS names are still not authorized, because only a name can be rebound. Only directly corresponding plain-HTTP origins are automatically allowed. A TLS proxy preserving `Host: panel.example` needs `allowed_hosts: 'panel.example'` and `allow_origins: 'https://panel.example'`; if it preserves `Host: panel.example:443`, add `allowed_hosts: 'panel.example', 'panel.example:443'`. Forwarded headers do not grant authorization.

Lists use individually quoted comma-separated entries, such as `allow_origins: 'http://localhost:3000', 'https://panel.example'`. Omit a list to leave it empty; JSON brackets and a single aggregate-quoted list are not accepted.

Relative UI paths follow the existing dependency search: an existing path under `global.data_dir`, then `/var/share/honk`, then the working directory; a missing dependency resolves under `global.data_dir` and startup fails. The administrator owns the directory and any symlink targets. See the [native API contract](./api.md#native-api-m1).

For a single binary, build `cargo build -p honk-core --features native-ui` and use `ui: embedded`; `native-ui` includes `native-api` without requiring Clash. Without `native-ui`, enabled embedded hosting fails startup. The assets receive no injected credentials; clients use public discovery to select static-token entry or password setup/login. Asset/source identities, corresponding-source distribution and the M9 management contract are documented in the [API reference](./api.md#embedded-doona-provenance).

Geodata sources are administrator-controlled, restart-required and cannot be changed through source writes. Userinfo, fragments, redirects and content encoding are rejected. Hostname sources require `global.bootstrap_resolver`; no system-DNS fallback or proxy detour is used. All loaded assets need a configured source before updates are available. The [M9 contract](./api.md#managed-entries-and-geodata-m9) distinguishes network limits, verified-byte activation and partial durable replacement from rollback.

Traffic and memory histories share the existing one-second sampler; missing samples/measurements remain gaps/nulls rather than zero-filled or interpolated points. Memory is actual process RSS and available cgroup-v2 data, not kernel accounting. File settings remain restart-required. `PATCH /api/v1/runtime/settings` can transiently adjust the supported log/DNS-log/flow limits and native log level, but cannot enable a disabled recorder. Accepted explicit activation, including no-op, restores configured values; provider/network refresh and suspend/resume preserve overrides.

Configuration metadata, validation and reload operations require a genuine `.dae` source snapshot captured at startup; programmatic configs and compatibility serde loaders do not supply one. Configuration reads expose accepted content, masking only declared listener-secret values, including duplicate/overridden values and their other occurrences. Admitted anonymous loopback requests read the same data as bearer-authenticated requests. Credential-bearing sources stay read-only and retain original-byte hashes. Source `path` stays entry-directory-relative; `absolute_path` exposes the canonical absolute path. Move credentials to a dedicated read-only include locally if the main source must be editable. The API cannot change/move API credentials or alter native settings; those require a local edit and restart.

`config_content` and `writable_includes` are accepted and ignored. With `config_write: true`, all accepted noncredential includes are writable; ordinary `include` glob and no-match semantics remain unchanged. Save by opaque source ID with a strong disk-content SHA-256 `If-Match`, then follow the real reload operation. A successful write is not activation success, and externally uncoordinated editors can still race the final check/rename window. Restricted Group PATCH uses the same source transaction but requires the accepted group/config ETag, checked before writing and again before activation; that revision is not the disk hash. See [source safety and failure semantics](./api.md#accepted-configuration-and-reload-operations-m6).

Probe requests cannot supply URLs or allowlist exceptions. For an intentionally local test target, an administrator might set `probe_allowed_cidrs: '127.0.0.1/32'` and `probe_allowed_ports: '18080'`; authorize only the necessary destinations/ports. Resolution checks and address pinning still apply. Native source writes cannot change these allowlists.

## `clash_api`

| Field | Default | Meaning |
| --- | --- | --- |
| `external_controller` | `""` | HTTP listen address. An empty value disables the API server. |
| `external_ui` | `""` | External dashboard directory. An empty value disables dashboard serving and download. |
| `external_ui_download_url` | `""` | HTTP(S) dashboard ZIP URL. An empty value uses the built-in zashboard URL. |
| `external_ui_download_detour` | `""` | Node or group tag used for the download. An empty value follows normal traffic routing. |
| `secret` | `""` | API authentication secret. An empty value disables authentication. A value shorter than 8 bytes is not masked in native API responses. |
| `default_mode` | `"Rule"` | Startup mode when native API is disabled: `Rule`, `Global`, or `Direct`; a valid cached mode takes precedence. Native-enabled startup uses shared transient rule mode instead. |

All `clash_api` fields are startup-owned. SIGHUP rejects a candidate configuration that changes any of them.

### Authentication and transport

With a non-empty `secret`, API requests use `Authorization: Bearer <secret>`; WebSocket upgrades may instead pass `?token=<secret>`. Static `/ui` content is outside this authentication middleware. The built-in listener serves plain HTTP and provides no TLS. Bind it to a loopback address such as `127.0.0.1`, or put an authenticated TLS reverse proxy in front of it; do not expose it directly on an untrusted network. See the [Clash API reference](./api.md) for the endpoint inventory.

An explicitly enabled non-loopback bind with an empty secret emits `unsafe-api-bind` at `experimental.clash_api.external_controller`, including structured input. The diagnostic contains neither the endpoint nor the secret. Loopback sample configurations do not warn; this warning does not change bind, authentication, or CORS policy.

### External UI

An absolute `external_ui` path is used literally. A relative path selects an existing directory below `global.data_dir` first, then an existing directory below `/var/share/honk`, then an existing working-directory-relative directory; if none exists, honk creates the target below `global.data_dir`. A missing or empty target triggers a background dashboard ZIP download. A non-empty `external_ui_download_url` replaces the built-in zashboard URL; `HONK_UI_DOWNLOAD_URL` has highest precedence over both.

A non-empty `external_ui_download_detour` forces the initial request and every redirect through that node or group. `direct` downloads directly, `block` aborts, and a group resolves its authoritative leaf for each exchange. When the field is empty, each URL follows the normal traffic routing decision as before. An unavailable tag, download failure, or extraction failure is logged without stopping the engine.

### Startup mode

With native disabled, `default_mode` accepts `Rule`, `Global`, and `Direct`; a valid cached Clash mode takes precedence, and invalid values fall back to `Rule`. With native enabled, both APIs use one transient mode owner: no mode restore/persistence, rule at startup and every accepted explicit activation (including no-op), and preservation across provider/network refresh or suspend/resume. Native global mode targets a stable node/group identity and fails closed if refresh removes it. See [runtime mode](./api.md#connection-closing-mode-and-datapath-lifecycle).

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

Whenever `enabled` successfully opens the database, honk persists per-network Selector choices and each node's last real delay sample independently of `store_fakeip` and `store_dns`. Clash mode is restored/persisted only with native API disabled. Delay samples are snapshotted every minute; restoration discards malformed, zero, or older-than-24-hour samples. Liveness is not restored.

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
