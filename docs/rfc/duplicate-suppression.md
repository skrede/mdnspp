# Duplicate Answer Suppression

During the 20–120 ms response aggregation delay a responder listens to all
multicast traffic on the segment. If another responder has already multicast
an identical answer record with a TTL at least as large as the local TTL, the
local responder suppresses that record from its own pending response. This
prevents two hosts from sending the same data within milliseconds of each
other.

**RFC Reference:** RFC 6762 section 7.4

## Example

Duplicate answer suppression is always active in `service_server`. No user
configuration is required:

```cpp
#include <mdnspp/defaults.h>
#include <mdnspp/service_info.h>

int main()
{
    mdnspp::context ctx;

    mdnspp::service_info info{
        .service_name = "MyPrinter._http._tcp.local.",
        .service_type = "_http._tcp.local.",
        .hostname     = "printer.local.",
        .port         = 631,
        .address_ipv4 = "192.168.1.50",
    };

    // Duplicate suppression monitors multicast during the response delay.
    // If another host answers first with the same data and sufficient TTL,
    // those records are omitted from this server's response automatically.
    mdnspp::service_server srv{ctx, std::move(info)};

    srv.async_start(
        [](std::error_code ec) { /* ready */ },
        [&ctx](std::error_code) { ctx.stop(); });

    ctx.run();
}
```

See also: [examples/service_server/](../../examples/service_server/)

## Compliance Status

| Status | Aspect | Notes |
|--------|--------|-------|
| Implemented | Multicast monitoring during response delay | Server observes all incoming answer records during 20–120 ms window |
| Implemented | Suppression when `observed_ttl >= our_ttl` | RFC 6762 section 7.4 threshold (100%), not the 50% rule from section 7.1 |
| Implemented | Per-record suppression | Individual answers are suppressed; the remaining records are still sent |

## In-Depth

### Suppression algorithm

The `detail::duplicate_suppression_state` accumulates observed records via
`observe(record, ttl)`. Each call appends a `seen_answer` to an internal
vector. The vector uses a linear scan — the set of pending answers per
response is always small (typically fewer than 5 records for a single service),
so hashing overhead is not justified.

When the response timer fires, each pending answer record is checked with
`is_suppressed(record, our_ttl)`. The check iterates `m_seen` and returns
`true` if any entry satisfies:

```
record_identity_equal(seen.record, record) && seen.observed_ttl >= our_ttl
```

`record_identity_equal` compares name, DNS class, and rdata equality. TTL is
intentionally excluded from identity: two records are identical if they carry
the same data for the same name and type, regardless of the TTL they arrived
with.

### Threshold: 100% not 50%

RFC 6762 section 7.1 (known-answer suppression) uses a 50% TTL threshold:
the querier's known TTL must be at least half the record's original TTL for
suppression to apply. Section 7.4 is different: any observed TTL that is at
least as large as the local TTL suppresses the answer. mdnspp follows the
section 7.4 rule exactly.

### Scope

Suppression only applies to the immediate response being built. After the
response timer fires and any remaining records are sent, `duplicate_suppression_state::reset()`
clears the seen-answer list. The next query triggers a fresh observation window.

### Implementation references

- `mdnspp/detail/duplicate_answer_suppression.h` — `duplicate_suppression_state`,
  `seen_answer`, `is_suppressed`, `observe`
- `mdnspp/record_cache.h` — `record_identity_equal`, `rdata_equal`

## See Also

- [Traffic Reduction](traffic-reduction.md) — response delay during which suppression runs
- [Known-Answer Suppression](known-answer-suppression.md) — complementary mechanism (section 7.1)
- [service_server API](../api/service_server.md)
