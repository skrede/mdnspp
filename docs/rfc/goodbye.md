# Goodbye Packets

mdnspp sends goodbye packets when a service server shuts down, telling
network caches to flush the server's records immediately. Without goodbye
packets, peers would hold stale records until their TTL expires — up to
4500 seconds by default.

**RFC Reference:** RFC 6762 section 10.1

## Example

Goodbye packets are sent by default. To disable them:

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
        .send_goodbye = false, // no goodbye on shutdown
    };

    mdnspp::service_server srv{ctx, std::move(info), std::move(opts)};

    srv.async_start(
        [](std::error_code ec)
        {
            if (!ec)
                std::cout << "server is live (no goodbye on stop)\n";
        },
        [&ctx](std::error_code)
        {
            ctx.stop();
        });

    ctx.run();
}
```

See also: [examples/service_server/](../../examples/service_server/)

## Compliance Status

| Status | Aspect | Notes |
|--------|--------|-------|
| Implemented | Goodbye packet (TTL=0) on shutdown | Sent when `send_goodbye = true` (default) |
| Implemented | Goodbye sent from live or announcing state only | No goodbye during probe phase — nothing to retract |
| Implemented | Best-effort synchronous send | No completion handler; single multicast UDP packet |
| Implemented | Cache-side goodbye handling | `record_cache` retains TTL=0 records for 1 s before eviction |

## In-Depth

### Send path

When `stop()` is called on a `service_server` (or the destructor runs) and the
`send_goodbye` option is `true`, the server re-sends all of its resource
records with TTL set to 0. This is a single multicast UDP packet sent to the
configured multicast group before the receive loop is torn down.

A TTL of 0 tells mDNS caches on the network to flush the associated records.
Without goodbye packets, other hosts would continue to cache stale records
until their original TTL expires (4500 seconds by default).

Goodbye packets are sent synchronously during `stop()` — they are best-effort
UDP and do not use completion handlers. The server sends the goodbye from the
`live` or `announcing` state only; if the server is still probing when `stop()`
is called, no goodbye is sent (there was nothing to retract).

### Cache-side TTL=0 handling

`record_cache` follows RFC 6762 section 10.1 by retaining TTL=0 (goodbye)
records for 1 second before eviction. This 1-second hold prevents immediate
re-caching of the record if a simultaneous announcement races with the goodbye.
The effective TTL for storage purposes is forced to 1 when the wire TTL is 0.

### Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `send_goodbye` | `bool` | `true` | Send TTL=0 records on shutdown. |

This field is part of `service_options`. See
[service_options](../api/service_options.md) for the full struct reference.

## See Also

- [service_options](../api/service_options.md)
- [service_server](../api/service_server.md)
- [Probing and Conflict Resolution](probing.md) — the lifecycle leading up to goodbye
- [Cache-Flush Bit](cache-flush.md) — section 10.2, related cache eviction mechanism
