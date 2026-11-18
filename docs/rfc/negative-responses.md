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
| Implemented | NSEC in additional section | Included automatically when a queried name exists but the queried type does not |
| Implemented | Per-question owner name | The NSEC owner is the queried name whose type does not exist (service type, instance name, or hostname) |
| Implemented | Truthful type bitmap | The bitmap lists exactly the types that DO exist at that owner name (RFC 4034 §4.1.2 window block 0) |
| Implemented | Authoritative scope | Only generated for names the server is authoritative for |
| Implemented | Never suppressed (§6.1) | NSEC assertions are exempt from known-answer suppression |
| Not implemented | Querier-side NSEC consumption | Received NSEC records are not used to suppress querier retries |

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

`service_server` includes NSEC records in the additional section when a query
names one of its owned names (service type, service instance name, or
hostname) with a record type that does not exist at that name. The NSEC owner
is the specific queried name — a query for `myhost.local. PTR` yields an NSEC
owned by `myhost.local.`, not by the instance name — and the type bitmap
lists exactly the types that do exist at that owner. For example, a server
with only an IPv4 address responding to a combined A+AAAA query for its
hostname answers the A record and adds an NSEC owned by the hostname whose
bitmap contains A (and not AAAA).

### Interaction with known-answer suppression

NSEC assertions are never suppressed by known-answer suppression (RFC 6762
§7.1 suppression applies to the positive answer records only). Conversely,
mdnspp's queriers do not currently consume received NSEC records to suppress
their own retries.

## See Also

- [known-answer-suppression](known-answer-suppression.md)
- [probing](probing.md)
- [RFC Compliance](README.md)
