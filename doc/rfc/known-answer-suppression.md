# Known-Answer Suppression

mdnspp suppresses redundant responses when the querier already knows the
answer, reducing multicast traffic on the network.

**RFC Reference:** RFC 6762 section 7.1

## How mdnspp implements this

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
suppression can take effect -- this avoids vacuous suppression where no
records would have been sent regardless.

### Client side

The querier and service discovery classes include known records in their query
packets. When sending a PTR query, the known-answer records from previous
results are appended to the query's Answer section, allowing responding
servers to suppress records the querier already has.

## Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `suppress_known_answers` | `bool` | `true` | Enable server-side known-answer suppression. |

This field is part of `service_options`. See
[service_options](../api/service_options.md) for the full struct reference.

Client-side known-answer inclusion is always active and requires no
configuration.

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

## See Also

- [service_options](../api/service_options.md)
- [Traffic Reduction](traffic-reduction.md) -- other mechanisms that reduce network load
