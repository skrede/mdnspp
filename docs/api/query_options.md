# query_options

## Overview

`query_options` controls the behavior of a querier or service discovery
instance: an optional per-record callback invoked as records arrive, an
optional error handler, and a silence timeout that determines how long to
wait after the last relevant packet before completing. Construct with
`query_options{}` and the silence timeout is 3 seconds with no callbacks.

**Header:**

```cpp
#include <mdnspp/query_options.h>
```

Included transitively by `#include <mdnspp/defaults.h>`.

## query_options struct

```cpp
#include <mdnspp/callback_types.h>

namespace mdnspp {

struct query_options
{
    using record_callback = mdnspp::record_callback;
    using error_handler = mdnspp::error_handler;

    record_callback on_record{};
    error_handler on_error{};
    std::chrono::milliseconds silence_timeout{3000};
};

}
```

`record_callback` and `error_handler` are defined in `<mdnspp/callback_types.h>` (included transitively).

## Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `on_record` | `record_callback` | `{}` (none) | Called once per parsed DNS record with the sender endpoint and record variant. |
| `on_error` | `error_handler` | `{}` (none) | Called on fire-and-forget send failures and fatal receive errors with the error code and a context string (e.g. `"query send"`, `"receive"`). |
| `silence_timeout` | `std::chrono::milliseconds` | `3000` (3 seconds) | How long to wait after the last relevant packet before completing. Must be positive: the peer constructors validate the options and reject a non-positive timeout with `std::errc::invalid_argument`. |

### on_record

Called each time a DNS record is parsed from an incoming mDNS response. The
callback receives the sender endpoint (address and port) and the record
variant. Use this for streaming output &mdash; printing or processing records as
they arrive rather than waiting for the final result set.

**Default:** None (records are still accumulated internally).

```cpp
mdnspp::query_options opts{
    .on_record = [](const mdnspp::endpoint &sender,
                    const mdnspp::mdns_record_variant &rec)
    {
        std::visit([&](const auto &r) {
            std::cout << sender << " -> " << r << std::endl;
        }, rec);
    }
};
```

### on_error

Called when a fire-and-forget send fails or the receive loop encounters a
fatal error. The error code describes the failure; the string view names the
failure site. Without a handler, these errors are silently ignored.

**Default:** None.

```cpp
mdnspp::query_options opts{
    .on_error = [](std::error_code ec, std::string_view context)
    {
        std::cerr << context << ": " << ec.message() << std::endl;
    }
};
```

### silence_timeout

The silence timeout determines how long the querier or discovery instance
waits after receiving the last relevant packet before firing the completion
handler. A shorter timeout completes faster but may miss late responders; a
longer timeout catches slow devices but delays completion.

**Default:** `3000ms` (3 seconds) &mdash; a conventional mDNS default.

```cpp
mdnspp::query_options opts{.silence_timeout = std::chrono::seconds(5)};
```

## Usage Examples

### Minimal (all defaults)

```cpp
mdnspp::context ctx;

mdnspp::querier q{ctx};

q.async_query("_http._tcp.local.", mdnspp::dns_type::ptr,
    [&ctx](std::error_code ec, std::vector<mdnspp::mdns_record_variant> results)
    {
        std::cout << results.size() << " record(s)" << std::endl;
        ctx.stop();
    });

ctx.run();
```

### With per-record callback

```cpp
mdnspp::context ctx;

mdnspp::service_discovery sd{ctx,
    mdnspp::query_options{
        .on_record = [](const mdnspp::endpoint &sender,
                        const mdnspp::mdns_record_variant &rec)
        {
            std::visit([&](const auto &r) {
                std::cout << sender << " -> " << r << std::endl;
            }, rec);
        }
    }
};

sd.async_discover("_http._tcp.local.",
    [&ctx](std::error_code ec, const std::vector<mdnspp::mdns_record_variant> &results)
    {
        std::cout << "complete -- " << results.size() << " record(s)" << std::endl;
        ctx.stop();
    });

ctx.run();
```

### Custom silence timeout

```cpp
mdnspp::context ctx;

mdnspp::querier q{ctx,
    mdnspp::query_options{.silence_timeout = std::chrono::milliseconds(500)}
};
```

## See Also

- [querier](querier.md) -- the querier that uses `query_options`
- [service_discovery](service_discovery.md) -- service discovery that uses `query_options`
- [observer_options](observer_options.md) -- options for the observer (no silence timeout)
- [Socket Options](../socket-options.md) -- network-level configuration
