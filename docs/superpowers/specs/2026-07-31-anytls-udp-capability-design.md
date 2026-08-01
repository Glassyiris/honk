# AnyTLS UDP capability and warm-up design

## Context

The UDP warm coordinator can select an AnyTLS node configured with `network: tcp`. `OutboundCapabilities::for_node` currently derives UDP support from protocol alone, while the AnyTLS transport rejects UDP later from `node.network`. Warm-up can therefore open a session that no UDP flow may use and count a misleading warm attempt.

## Decision

Make UDP capability represent end-to-end configured support:

1. `OutboundCapabilities::for_node` keeps the existing protocol support matrix, then intersects it with the comma-separated `node.network` allowlist. Missing `network` preserves current behavior; matching is trimmed and ASCII-case-insensitive.
2. `udp_warm_candidates` consults the captured generation's `NodeRuntime.capabilities.udp` and excludes nodes that cannot carry UDP before dispatch or metrics are produced.
3. AnyTLS `warm_pool_with` independently returns `UdpWarmStatus::NotApplicable` when the captured runtime lacks UDP capability. This is a fail-closed guard for direct callers and future coordinator changes; it must run before janitor creation or dialing.

## Scope boundaries

This change does not alter protocol selection, group resolution, ordinary TCP dialing, UDP framing, or session ownership. It does not address the pre-existing AnyTLS terminal-event, overflow notification, `poll_write`, or UoT stream-framing findings inherited from the `dev` merge parent.

## Verification

RED/GREEN tests will prove:

- AnyTLS with no network restriction or an allowlist containing `udp` remains UDP-capable.
- AnyTLS with a TCP-only allowlist is not UDP-capable.
- TCP-only AnyTLS warm-up returns `NotApplicable` without invoking the dial closure or creating a pooled session.
- Authoritative warm candidate discovery excludes a TCP-only AnyTLS leaf while retaining a UDP-enabled leaf.

Run focused runtime, AnyTLS warm, and reload warm-candidate tests, followed by `ci/outbound-ci.sh`, `ci/dns-ci.sh`, formatting, Clippy, and diagnostics.
