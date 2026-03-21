# Negative Responses (NSEC)

RFC 6762 §6.1 allows a responder to explicitly indicate the absence of records for a
queried name using NSEC (Next Secure) records in the additional section of an mDNS
response. A negative response tells queriers that the responder is authoritative for the
queried name and that no records of the requested type exist, preventing unnecessary
retries.

**RFC Reference:** RFC 6762 §6.1

## Example

Negative responses are generated automatically by `service_server` when it receives a
query for a name it owns but for a record type it does not have:

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
        // no address_ipv6 field — AAAA queries will receive an NSEC negative response
    };

    mdnspp::service_server srv{ctx, std::move(info)};

    srv.async_start();
    ctx.run();
}
```

When a remote host queries for an AAAA record for `myhost.local.` and the service server
has no IPv6 address, it responds with an NSEC record indicating that no AAAA record
exists for that name.

## Compliance Status

| Status | Aspect | Notes |
|--------|--------|-------|
| Implemented | NSEC in additional section | Included automatically when a positive answer does not cover all queried types |
| Implemented | Per-type absence indication | NSEC bitmap covers the specific missing record types |
| Implemented | Authoritative scope | Only generated for names the server is authoritative for |

## In-Depth

### NSEC record structure

An NSEC record in mDNS (repurposed from DNSSEC, RFC 4034 §4) carries:
- **Owner name**: the domain name for which absence is asserted.
- **Next Domain Name**: in mDNS NSEC records this is the same as the owner name
  (the record is a "compact" NSEC, not a full DNSSEC chain).
- **Type Bit Maps**: a bitmap of the DNS record types that DO exist for this name.

A querier that receives an NSEC record can infer that any type absent from the bitmap
does not exist at that name under the current authoritative owner. This suppresses
retries and speeds up negative caching.

### When mdnspp generates NSEC records

`service_server` includes NSEC records in the additional section when responding to a
query for a name it owns, if the response does not contain all record types that could
be queried for that name. For example, a server with only an IPv4 address will include
an NSEC record asserting no AAAA exists when responding to a combined A+AAAA query.

### Interaction with known-answer suppression

NSEC records participate in known-answer suppression: a querier that includes a valid
NSEC record in its known-answer list suppresses a redundant negative response from
the server, reducing unnecessary traffic.

## See Also

- [known-answer-suppression](known-answer-suppression.md)
- [probing](probing.md)
- [RFC Compliance](README.md)
