# QU/QM Response Routing

RFC 6762 §5.4 defines two classes of mDNS queries: QU (Query requesting Unicast
response) and QM (Query requesting Multicast response). A querier sets the
QU bit (the top bit of the QCLASS field in the DNS question) to indicate that
it prefers a unicast response. Responders examine this bit to decide where to
send their answers.

**RFC Reference:** RFC 6762 §5.4

## Example

QU/QM routing is automatic and requires no user configuration. A `service_server`
respects the QU bit in incoming queries and sends the response to the correct
destination:

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

    mdnspp::service_server srv{ctx, std::move(info)};

    srv.async_start();
    ctx.run();
}
```

No explicit QU/QM configuration is exposed; the implementation follows RFC 6762 §5.4
automatically for every incoming query.

## Compliance Status

| Status | Aspect | Notes |
|--------|--------|-------|
| Implemented | QU bit detection | Reads the top bit of QCLASS in incoming questions |
| Implemented | Unicast response routing | QU queries receive a unicast response to the sender |
| Implemented | Multicast response routing | QM queries receive a multicast response |
| Implemented | Probe QU queries | Outgoing probes use QU to reduce multicast load during probing |

## In-Depth

### QU semantics

A question with the QU bit set signals that the querier is willing to accept a
unicast response. This is used in two scenarios:

1. **First-time queries**: A fresh querier that has not yet heard recent multicast
   traffic sets QU to avoid unnecessary multicast responses from all responders on
   the link.

2. **Probing**: During RFC 6762 §8 probing, outgoing probes use QU queries so that
   only the authoritative responder for the name replies, reducing multicast
   traffic on the segment.

### QM semantics

A question without the QU bit set (the default) expects a multicast response.
This is appropriate for queries that seek all responders, not just one.

### Response routing rules (RFC 6762 §6)

When a `service_server` receives a query:
- If the QU bit is set and the server has recently sent a multicast answer for
  this record, it may suppress the unicast response (the recent multicast answer
  already satisfies the querier).
- If the QU bit is set and no recent multicast answer is available, the response
  is sent unicast to the querier's address and port.
- If the QU bit is clear (QM query), the response is multicast to `224.0.0.251:5353`
  (IPv4) or `[ff02::fb]:5353` (IPv6).

## See Also

- [probing](probing.md) — QU queries during probe phase
- [tc-handling](tc-handling.md) — TC bit and known-answer handling
- [RFC Compliance](README.md)
