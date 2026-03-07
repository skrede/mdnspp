# Goodbye Packets

mdnspp sends goodbye packets when a service server shuts down, telling
network caches to flush the server's records immediately.

**RFC Reference:** RFC 6762 section 10.1

## How mdnspp implements this

When `stop()` is called on a `service_server` (or the destructor runs) and the
`send_goodbye` option is `true`, the server re-sends all of its resource
records with TTL set to 0. This is a single multicast UDP packet sent to
224.0.0.251:5353 before the receive loop is torn down.

A TTL of 0 tells mDNS caches on the network to flush the associated records.
Without goodbye packets, other hosts would continue to cache stale records
until their original TTL expires (4500 seconds by default).

Goodbye packets are sent synchronously during `stop()` -- they are
best-effort UDP and do not use completion handlers. The server sends the
goodbye from the `live` or `announcing` state only; if the server is still
probing when `stop()` is called, no goodbye is sent (there was nothing to
retract).

## Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `send_goodbye` | `bool` | `true` | Send TTL=0 records on shutdown. |

This field is part of `service_options`. See
[service_options](../api/service_options.md) for the full struct reference.

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

## See Also

- [service_options](../api/service_options.md)
- [service_server](../api/service_server.md)
- [Probing and Conflict Resolution](probing.md) -- the lifecycle leading up to goodbye
