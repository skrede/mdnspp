# Known-Answer Suppression

mdnspp suppresses redundant responses when the querier already knows the
answer, reducing multicast traffic on the network. When a query includes
answer records that the server would otherwise send, those records are omitted
from the response — or the response is skipped entirely if all records are
suppressed.

**RFC Reference:** RFC 6762 section 7.1

## Example

Known-answer suppression is enabled by default. No special setup is needed:

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

    // suppress_known_answers defaults to true -- nothing extra needed
    mdnspp::service_server srv{ctx, std::move(info)};

    srv.async_start(
        [](std::error_code ec)
        {
            if (!ec)
                std::cout << "server is live with KAS enabled\n";
        },
        [&ctx](std::error_code)
        {
            ctx.stop();
        });

    ctx.run();
}
```

To disable suppression (not recommended):

```cpp
mdnspp::service_options opts{
    .suppress_known_answers = false,
};
mdnspp::service_server srv{ctx, std::move(info), std::move(opts)};
```

See also: [examples/service_server/](../../examples/service_server/)

## Compliance Status

| Status | Aspect | Notes |
|--------|--------|-------|
| Implemented | Server-side known-answer suppression | Enabled by default; configurable via `suppress_known_answers` |
| Implemented | Per-record-type suppression | PTR, SRV, A, AAAA, TXT suppressed independently |
| Implemented | Full-response suppression when all records are suppressed | Response skipped if nothing remains to send |
| Implemented | Client-side known-answer inclusion | Querier and discovery classes append known records to outgoing queries |
| Implemented | 50% TTL threshold | Record suppressed only when known TTL >= half of original TTL |

## In-Depth

### Server side

When the server receives a query that contains answer records in its Answer
section, it compares each answer against its own authoritative records. If an
answer record's TTL is at least half of the record's original TTL (the
suppression threshold is `4500 / 2 = 2250` seconds), the server suppresses
that record type from its response.

If all record types that would have been included in the response are
suppressed, the server skips the response entirely. Partial suppression is
also supported: individual record types (PTR, SRV, A, AAAA, TXT) are
suppressed independently when queried with a specific type. For `ANY` queries,
all five types are checked.

The server requires at least one record type to actually be sendable before
suppression can take effect — this avoids vacuous suppression where no
records would have been sent regardless.

### Client side

The querier and service discovery classes include known records in their query
packets. When sending a PTR query, the known-answer records from previous
results are appended to the query's Answer section, allowing responding
servers to suppress records the querier already has.

Client-side known-answer inclusion is always active and requires no
configuration. The maximum number of known-answer records included per query
is configurable via `mdns_options::max_known_answers` (default: 0, unlimited).

### Relationship to duplicate answer suppression

Section 7.1 (this feature) and section 7.4 (duplicate answer suppression)
both suppress sending, but they operate differently:

- **Section 7.1** uses the 50% TTL threshold and is driven by records
  carried in the querier's own query packet.
- **Section 7.4** uses the 100% TTL threshold and is driven by observing
  multicast answers from other responders during the response delay window.

See [duplicate-suppression.md](duplicate-suppression.md) for section 7.4.

### Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `suppress_known_answers` | `bool` | `true` | Enable server-side known-answer suppression. |
| `max_known_answers` | `std::size_t` | `0` (unlimited) | Maximum known-answer records per outgoing query. |

`suppress_known_answers` is part of `service_options`; `max_known_answers` is
part of `mdns_options`. See the respective API pages for the full struct reference.

## See Also

- [service_options](../api/service_options.md)
- [mdns-options](../mdns-options.md) — `max_known_answers` tunable
- [Traffic Reduction](traffic-reduction.md) — other mechanisms that reduce network load
- [Duplicate Answer Suppression](duplicate-suppression.md) — section 7.4 complement
