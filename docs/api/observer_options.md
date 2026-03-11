# observer_options

## Overview

`observer_options` controls the behavior of an observer: an optional
per-record callback invoked as mDNS records are received. Construct with
`observer_options{}` for a silent observer, or provide a callback to process
records as they arrive.

**Header:**

```cpp
#include <mdnspp/observer_options.h>
```

Included transitively by `#include <mdnspp/defaults.h>`.

## observer_options struct

```cpp
#include <mdnspp/callback_types.h>

namespace mdnspp {

struct observer_options
{
    using record_callback = mdnspp::record_callback;

    record_callback on_record{};
};

}
```

`record_callback` is defined in `<mdnspp/callback_types.h>` (included transitively).

## Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `on_record` | `record_callback` | `{}` (none) | Called once per parsed DNS record with the sender endpoint and record variant. |

### on_record

Called each time a DNS record is parsed from an incoming mDNS packet. The
callback receives the sender endpoint (address and port) and the record
variant. Unlike the querier and service discovery, the observer has no
silence timeout -- it runs until `stop()` is called.

**Default:** None (the observer still runs but does nothing with records).

```cpp
mdnspp::observer_options opts{
    .on_record = [](const mdnspp::endpoint &sender,
                    const mdnspp::mdns_record_variant &rec)
    {
        std::visit([&](const auto &r) {
            std::cout << sender << " -> " << r << "\n";
        }, rec);
    }
};
```

## Usage Examples

### Minimal (no callback)

```cpp
mdnspp::context ctx;

mdnspp::observer obs{ctx};
obs.async_observe([&ctx](std::error_code) { ctx.stop(); });
ctx.run();
```

### With per-record callback

```cpp
mdnspp::context ctx;
int count = 0;

mdnspp::observer obs{ctx,
    mdnspp::observer_options{
        .on_record = [&](const mdnspp::endpoint &sender,
                         const mdnspp::mdns_record_variant &rec)
        {
            std::visit([&](const auto &r) {
                std::cout << sender << " -> " << r << "\n";
            }, rec);

            if (++count >= 5)
                obs.stop();
        }
    }
};

obs.async_observe([&ctx](std::error_code) { ctx.stop(); });
ctx.run();
```

### With socket options

```cpp
mdnspp::context ctx;
mdnspp::socket_options sock{.interface_address = "192.168.1.10"};

mdnspp::observer obs{ctx,
    mdnspp::observer_options{.on_record = my_callback},
    sock
};
```

## See Also

- [observer](observer.md) -- the observer that uses `observer_options`
- [query_options](query_options.md) -- options for querier and service discovery (includes silence timeout)
- [Socket Options](../socket-options.md) -- network-level configuration
