# announce_subtypes in service_options

| | |
|---|---|
| **Type** | `bool` |
| **Default** | `false` |
| **One-liner** | Whether to announce sub-type PTR records (e.g., `_printer._sub._http._tcp.local.`) alongside the main PTR record. |

## What

DNS-SD (RFC 6763 §7) supports service subtypes: a service may be discoverable under one or more sub-type names in addition to its primary service type. For example, a printer service could advertise both `_http._tcp.local.` (primary) and `_printer._sub._http._tcp.local.` (sub-type).

With `announce_subtypes = true`, the service server includes PTR records for all configured subtypes during announcement. With `false` (the default), only the primary service type PTR record is announced; subtypes are answered only when directly queried.

Subtypes are configured via the `service_info` structure passed to the service server, not through `service_options` directly.

## Why

Set `announce_subtypes = true` when:

- The service uses DNS-SD subtypes and wants them discoverable via unsolicited announcements.
- Clients on the network use subtype-based discovery and may not issue a query before the service's initial announcement window passes.

Keep `announce_subtypes = false` (the default) when:

- No subtypes are configured (the default has no effect in that case).
- Minimising announcement packet size is important.

## Danger

- **Enabling with many subtypes increases the announcement packet count and size.** Each subtype adds one PTR record to every announcement packet.
- If announcement packets grow large enough (beyond `mdns_options::max_query_payload`), they may be fragmented. Keep the total subtype count small.
- Subtype records are always answered in response to direct queries regardless of this flag; `announce_subtypes` controls only unsolicited proactive announcements.
