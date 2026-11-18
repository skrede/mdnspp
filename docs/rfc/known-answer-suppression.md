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
                std::cout << "server is live with KAS enabled" << std::endl;
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
| Implemented | Rdata matching (§7.1) | A known answer suppresses only when its name, type, class AND rdata match the record the server would send; a stale SRV (old port) does not suppress the correct answer |
| Implemented | Per-record-type suppression | PTR, SRV, A, AAAA, TXT suppressed independently |
| Implemented | Full-response suppression when all records are suppressed | Response skipped if nothing remains to send |
| Implemented | Client-side known-answer inclusion | The continuous service monitor appends cached records to its scheduled PTR queries; one-shot querier and discovery operations start with an empty cache and send no known answers |
| Implemented | Half-TTL threshold per record type | Record suppressed only when known TTL >= `ka_suppression_fraction` (default 0.5) of the per-type TTL the server would send |

## In-Depth

### Server side

When the server receives a query that contains answer records in its Answer
section, it compares each answer against its own authoritative records.
Suppression requires the known answer to assert exactly the server's record:
matching owner name, type, class, and rdata (byte-exact for SRV/A/AAAA/TXT;
for PTR, the rdata target must equal the service instance name). A querier
holding stale rdata — for example an SRV with an old port — therefore still
receives the correct answer.

In addition, the known answer's TTL must be at least
`mdns_options::ka_suppression_fraction` (default 0.5, the RFC's half-TTL
rule) of the per-type TTL the server would send: `ptr_ttl`, `srv_ttl`,
`txt_ttl`, `a_ttl`, or `aaaa_ttl` from `service_options`. With the defaults
this is 2250 s for PTR/TXT and 60 s for SRV/A/AAAA.

If all record types that would have been included in the response are
suppressed, the server skips the response entirely. Partial suppression is
also supported: individual record types (PTR, SRV, A, AAAA, TXT) are
suppressed independently when queried with a specific type. For `ANY` queries,
all five types are checked.

The server requires at least one record type to actually be sendable before
suppression can take effect — this avoids vacuous suppression where no
records would have been sent regardless.

### Client side

The continuous `service_monitor` includes known answers in its scheduled PTR
queries: cached PTR records whose remaining TTL exceeds
`ka_suppression_fraction` (default 0.5) of their wire TTL are appended to
the query's Answer section, allowing responding servers to suppress records
the monitor already has. Queries exceeding
`mdns_options::max_query_payload` are split into TC continuation packets
(see [tc-handling.md](tc-handling.md)).

One-shot operations (`querier`, `service_discovery`) hold no record cache
when their single query is built, so their queries carry an empty Answer
section — they never suppress any responder.

The maximum number of known-answer records included per query is
configurable via `mdns_options::max_known_answers` (default: 0, unlimited).

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
