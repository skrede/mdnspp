# Legacy Unicast Responses

RFC 6762 §6.7 defines legacy unicast responses for compatibility with pre-mDNS DNS
resolvers. A legacy unicast query is identified by two properties: the source port is
not 5353, or the query ID (DNS message ID) is non-zero. When these conditions are met,
the responder sends a conventional DNS unicast response directly to the sender rather
than multicasting the answer.

The TTL of records in legacy unicast responses is intentionally capped at a small value
(10 seconds by default) to prevent non-mDNS resolvers from caching the records for too
long.

**RFC Reference:** RFC 6762 §6.7

## Example

Legacy unicast support is opt-in via `service_options`:

```cpp
#include <mdnspp/defaults.h>
#include <mdnspp/service_info.h>

int main()
{
    mdnspp::context ctx;

    mdnspp::service_info info{
        .service_name = "MyApp._http._tcp.local.",
        .service_type = "_http._tcp.local.",
        .hostname     = "myhost.local.",
        .port         = 8080,
        .address_ipv4 = "192.168.1.42",
    };

    mdnspp::service_options opts{
        .respond_to_legacy_unicast = true,  // default: true
    };

    // Control the TTL cap for legacy unicast responses via mdns_options
    mdnspp::mdns_options mdns_opts{
        .legacy_unicast_ttl = std::chrono::seconds{10},  // RFC default
    };

    mdnspp::service_server srv{ctx, std::move(info), std::move(opts), {}, mdns_opts};

    srv.async_start();
    ctx.run();
}
```

Legacy unicast response handling is enabled by default. To disable it, set
`service_options::respond_to_legacy_unicast = false`.

## Compliance Status

| Status | Aspect | Notes |
|--------|--------|-------|
| Implemented | Legacy unicast detection | Source port != 5353 or query ID != 0 |
| Implemented | Unicast response routing | Response sent directly to sender's address and port |
| Implemented | TTL cap on outgoing records | `mdns_options::legacy_unicast_ttl` (default 10 s) |
| Implemented | Configurable opt-out | `service_options::respond_to_legacy_unicast` |

## In-Depth

### What makes a query "legacy unicast"

RFC 6762 §6.7 identifies a legacy unicast query by either of:
- Source port is not 5353 (the dedicated mDNS port).
- The DNS message ID field is non-zero (standard mDNS sets ID=0).

Conventional DNS clients that use mDNS before the `.local.` pseudo-TLD was reserved
send queries from ephemeral ports with non-zero IDs. mdnspp detects these conditions
and routes its response accordingly.

### TTL capping

Records included in legacy unicast responses have their TTL capped at
`mdns_options::legacy_unicast_ttl` (default 10 seconds). This prevents DNS resolvers
that receive the unicast response from caching the mDNS record for the full mDNS
record TTL (typically 75 minutes). Short-lived caching is appropriate because these
resolvers do not monitor the mDNS multicast group for updates or goodbye packets.

### Multicast vs unicast routing

For a standard mDNS query (source port 5353, ID=0), the response is multicast to the
mDNS group address. For a legacy unicast query, the response is sent unicast to the
sender's exact address and port, matching the behavior of a conventional DNS server.

## See Also

- [service_options](../api/service_options.md) — `respond_to_legacy_unicast` field
- [mdns_options](../api/mdns_options.md) — `legacy_unicast_ttl` field
- [qujm-routing](quqm-routing.md) — standard QU/QM multicast and unicast routing
- [RFC Compliance](README.md)
