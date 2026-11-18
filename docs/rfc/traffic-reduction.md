# Traffic Reduction

mdnspp implements three traffic reduction mechanisms from RFC 6762 that are
always active. A random query delay prevents simultaneous query bursts; a
random response delay aggregates queries into a single response; and duplicate
question suppression cancels queries that another host has already issued.

**RFC Reference:** RFC 6762 section 5.2 (QM query delay), section 6 (response
delay and aggregation), section 7.3 (duplicate question suppression)

## Example

Traffic reduction is automatic. A standard querier benefits from all three
mechanisms without any special setup:

```cpp
#include <mdnspp/defaults.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;
    mdnspp::querier q{ctx};

    // The 20-120 ms QM delay and duplicate suppression happen automatically
    q.async_query("_http._tcp.local.", mdnspp::dns_type::ptr,
        [&ctx](std::error_code ec, std::vector<mdnspp::mdns_record_variant> results)
        {
            std::cout << results.size() << " record(s)" << std::endl;
            ctx.stop();
        });

    ctx.run();
}
```

See also: [examples/querier/](../../examples/querier/)

## Compliance Status

| Status | Aspect | Notes |
|--------|--------|-------|
| Implemented | QM query delay (20–120 ms random) | Applied before sending each multicast query |
| Implemented | QU queries sent immediately | No delay for unicast-response queries |
| Implemented | Response delay (20–120 ms random) | Applied before multicast responses containing shared records; responses consisting solely of probe-verified unique records are sent immediately (section 6) |
| Implemented | Query aggregation during response delay | Multiple query types merged into one response |
| Implemented | Duplicate question suppression (section 7.3) | Cancels pending query when a matching, known-answer-free QM query is seen from another host |
| Implemented | Legacy unicast responses (section 6.7) | See [legacy-unicast.md](legacy-unicast.md) |

## In-Depth

### QM query delay (section 5.2)

When the querier sends a multicast (QM) query, it delays sending by a random
interval between 20 and 120 ms. This prevents bursts of simultaneous queries
when multiple hosts start querying at the same time.

QU (unicast) queries are sent immediately with no delay.

### Response delay (section 6)

When the server receives a multicast query whose answer contains shared
records (PTR), it delays its response by a random interval between 20 and
120 ms (`mdns_options::response_delay_min` / `response_delay_max`). During
the delay window, additional queries for different record types are merged
into a single aggregated response.

Responses consisting solely of unique, probe-verified records (SRV, TXT,
A/AAAA) are sent immediately, as section 6 permits. Unicast responses are
also sent immediately without delay.

### Duplicate question suppression (section 7.3)

During the QM query delay window (before the query is actually sent), the
querier monitors incoming packets for queries from other hosts. If an
incoming QM query matches the querier's pending query (same name and type)
AND carries no known answers (ancount == 0), the querier cancels its own
query — the other host's query will elicit the same responses.

The empty-known-answer requirement is the section 7.3 rule: suppression is
permitted only when the observed query's known-answer section contains
nothing the suppressing host does not also hold. `basic_querier` holds no
known answers, so only a known-answer-free query may suppress its own.
Suppressing on a query that carries a full known-answer list would silence
exactly the responses the local querier still needs.

Duplicate detection only runs during the pre-send delay window. Once the
query has been sent, incoming queries from other hosts are ignored for
suppression purposes.

### Configuration

These mechanisms are always on per RFC 6762 and cannot be disabled. The
delay range is configurable via `mdns_options::response_delay_min` and
`mdns_options::response_delay_max` (defaults 20 ms and 120 ms, the
RFC-mandated range); the same range is used for the QM query delay and the
multicast response delay.

## See Also

- [querier](../api/querier.md)
- [service_server](../api/service_server.md) — response delay on the server side
- [Known-Answer Suppression](known-answer-suppression.md) — section 7.1 suppression
- [Duplicate Answer Suppression](duplicate-suppression.md) — section 7.4 suppression during response delay
