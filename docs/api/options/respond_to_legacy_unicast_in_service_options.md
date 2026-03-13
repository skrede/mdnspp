# respond_to_legacy_unicast in service_options

| | |
|---|---|
| **Type** | `bool` |
| **Default** | `true` |
| **RFC** | RFC 6762 §6.7 |
| **One-liner** | Whether to respond to legacy unicast queries (source port ≠ 5353); replies are sent with TTLs capped at `mdns_options::legacy_unicast_ttl`. |

## What

Legacy unicast queries arrive from a source port other than 5353. They are used by resolvers that implement DNS-SD-compatible discovery but do not use full mDNS (e.g., some Windows implementations, iOS device discovery in managed networks).

RFC 6762 §6.7 defines the response behaviour: when `respond_to_legacy_unicast = true`, the service sends a unicast reply with all TTL values capped at `mdns_options::legacy_unicast_ttl` (default 10 seconds) to prevent aggressive caching by non-mDNS resolvers. With `false`, legacy unicast queries are silently ignored.

## Why

Set `respond_to_legacy_unicast = false` when:

- The service is intended exclusively for mDNS clients on port 5353.
- Running integration tests that inject packets via non-5353 ports and want to avoid accidental legacy-unicast responses (the `tests/integration` suite uses this pattern).
- Strict RFC compliance environments where unicast responses to non-mDNS clients are undesired.

Keep `respond_to_legacy_unicast = true` (the default) when interoperability with legacy DNS-SD resolvers is needed.

## Danger

- **Disabling silences the service for resolvers that use legacy DNS-SD querying**, such as some Windows and iOS implementations that query from non-5353 ports.
- With the default `true`, legacy clients receive TTL-capped responses; increasing `mdns_options::legacy_unicast_ttl` beyond RFC recommendation risks non-mDNS cache pollution.
- Disabling is necessary for inject()-based tests that assign source ports ≥ 10000 to injectors; those ports fall into the legacy unicast detection path.
