# DNS-SD: Enumeration and Subtypes

mdnspp supports DNS-Based Service Discovery (DNS-SD) features for discovering
service types on the network and filtering discovery by subtype. These are
built on top of the standard mDNS query mechanism and require no extra
infrastructure beyond standard mDNS.

**RFC Reference:** RFC 6763 section 9 (service type enumeration), section 7.1
(selective instance enumeration via subtypes)

## Example

### Enumerate all service types

```cpp
#include <mdnspp/defaults.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;
    mdnspp::service_discovery sd{ctx};

    sd.async_enumerate_types(
        [&ctx](std::error_code ec, std::vector<mdnspp::service_type_info> types)
        {
            for (const auto &t : types)
                std::cout << t.type_name << "." << t.protocol << "." << t.domain << "\n";
            ctx.stop();
        });

    ctx.run();
}
```

### Discover services by subtype

```cpp
#include <mdnspp/defaults.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;
    mdnspp::service_discovery sd{ctx};

    sd.async_discover_subtype("_http._tcp.local.", "_printer",
        [&ctx](std::error_code ec, const std::vector<mdnspp::mdns_record_variant> &results)
        {
            std::cout << results.size() << " subtype record(s)\n";
            ctx.stop();
        });

    ctx.run();
}
```

See also: [examples/service_discovery/](../../examples/service_discovery/)

## Compliance Status

| Status | Aspect | Notes |
|--------|--------|-------|
| Implemented | Service type enumeration (section 9) | `async_enumerate_types()` via `_services._dns-sd._udp.local.` |
| Implemented | Subtype queries (section 7.1) | `async_discover_subtype()` constructs `_sub._service._tcp.local.` queries |
| Implemented | Server-side meta-query response | `respond_to_meta_queries` in `service_options` (default: `true`) |
| Implemented | Subtype PTR records in announcements | Opt-in via `announce_subtypes` in `service_options` |
| Not implemented | Configurable per-record TTL | All records use fixed 4500 s TTL |

## In-Depth

### Service type enumeration (section 9)

`async_enumerate_types()` queries the well-known meta-query name
`_services._dns-sd._udp.local.` with PTR type. Responding servers that have
`respond_to_meta_queries` enabled reply with PTR records pointing to their
service type (e.g., `_http._tcp.local.`).

The results are returned as a vector of `service_type_info` structs, each
containing the parsed service type name, protocol, and domain. Parsing is
done by `parse_service_type()`, which decomposes names like
`_http._tcp.local` into their components.

### Subtype queries (section 7.1)

`async_discover_subtype()` constructs a subtype query name in the form
`_subtype._sub._service._tcp.local.` and delegates to the standard
`async_discover()` flow. On the server side, when `announce_subtypes` is
enabled, the server includes subtype PTR records in its announcement burst.

Servers always respond to subtype queries for their registered subtypes,
regardless of the `announce_subtypes` setting. The `announce_subtypes` option
only controls whether subtype PTR records are included in unsolicited
announcements.

### Registering subtypes

Subtypes are registered on the server via the `subtypes` field of
`service_info`:

```cpp
mdnspp::service_info info{
    .service_name = "MyPrinter._http._tcp.local.",
    .service_type = "_http._tcp.local.",
    .hostname     = "printer.local.",
    .port         = 631,
    .address_ipv4 = "192.168.1.50",
    .subtypes     = {"_printer"},
};
```

### Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `respond_to_meta_queries` | `bool` | `true` | Respond to `_services._dns-sd._udp.local.` queries. |
| `announce_subtypes` | `bool` | `false` | Include subtype PTR records in announcement bursts. |

These fields are part of `service_options`. See
[service_options](../api/service_options.md) for the full struct reference.

## See Also

- [service_discovery](../api/service_discovery.md) — full API reference for discovery methods
- [service_options](../api/service_options.md) — server-side DNS-SD configuration
- [Probing and Conflict Resolution](probing.md) — server lifecycle for DNS-SD servers
