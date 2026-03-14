# respond_to_meta_queries in service_options

| | |
|---|---|
| **Type** | `bool` |
| **Default** | `true` |
| **One-liner** | Whether to respond to DNS-SD meta-queries for `_services._dns-sd._udp.local.`. |

## What

DNS-SD (RFC 6763 §9) defines a meta-query mechanism: querying `_services._dns-sd._udp.local.` returns PTR records enumerating all service types present on the local link. This allows browsers and discovery tools to list "all services" without knowing service types in advance.

With `respond_to_meta_queries = true` (the default), the service server responds to this meta-query by advertising a PTR record for its own service type (e.g., `_http._tcp.local.`). With `false`, the service remains invisible to meta-query browsers.

## Why

Set `respond_to_meta_queries = false` when:

- The service is internal or sensitive and should not appear in generic service browsers.
- Reducing unnecessary responses on bandwidth-constrained links.
- Privacy requirements dictate that the service type should not be advertised globally.

Keep `respond_to_meta_queries = true` (the default) for most services that should be publicly discoverable on the local link.

## Danger

- **Disabling makes the service invisible to `dns-sd -B` and similar browser tools**, which can complicate debugging and monitoring.
- The service is still reachable by direct queries for its service type; `respond_to_meta_queries` only affects the meta-discovery layer.
- On networks with many services, all responding to meta-queries, the meta-query response can become large. This is a network-level concern, not a per-service risk.
