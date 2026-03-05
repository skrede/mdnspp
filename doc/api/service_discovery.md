# service_discovery

Discovers mDNS services by type on the local network. Offers two levels of abstraction: `async_discover` returns raw DNS records, while `async_browse` returns fully-resolved [`resolved_service`](resolved_service.md) values with hostname, port, addresses, and TXT metadata already correlated.

## Header and Alias

| Form | Header |
|------|--------|
| `basic_service_discovery<P>` | `#include <mdnspp/basic_service_discovery.h>` |
| `mdnspp::service_discovery` (DefaultPolicy alias) | `#include <mdnspp/defaults.h>` |

```cpp
// Template form
template <Policy P>
class basic_service_discovery;

// DefaultPolicy alias (from defaults.h)
using service_discovery = basic_service_discovery<DefaultPolicy>;
```

## Template Parameters

| Parameter | Constraint | Description |
|-----------|------------|-------------|
| `P` | satisfies `Policy` | Provides `executor_type`, `socket_type`, and `timer_type`. See [policies](../policies.md). |

## Type Aliases

```cpp
using executor_type      = typename P::executor_type;
using socket_type        = typename P::socket_type;
using timer_type         = typename P::timer_type;
using record_callback    = std::move_only_function<void(const mdns_record_variant&, endpoint)>;
using completion_handler = std::move_only_function<void(std::error_code, std::vector<mdns_record_variant>)>;
```

## Constructors

### Throwing

```cpp
explicit basic_service_discovery(executor_type ex,
                                 std::chrono::milliseconds silence_timeout,
                                 record_callback on_record = {});
```

Constructs the service discovery from an executor, a silence timeout, and an optional per-record callback. The `silence_timeout` determines how long to wait after the last relevant packet before completing. Throws on socket construction failure.

### Non-throwing

```cpp
basic_service_discovery(executor_type ex,
                        std::chrono::milliseconds silence_timeout,
                        record_callback on_record,
                        std::error_code& ec);

basic_service_discovery(executor_type ex,
                        std::chrono::milliseconds silence_timeout,
                        std::error_code& ec);
```

Same as the throwing constructor, but sets `ec` instead of throwing on failure.

## Methods

### async_discover

```cpp
void async_discover(std::string_view service_type, completion_handler on_done);
```

Sends a PTR query for `service_type` to the mDNS multicast group and collects **raw DNS records** until the silence timeout expires. The `on_done` handler receives all accumulated records (PTR, SRV, A, AAAA, TXT) as a flat vector.

Use this when you need access to individual DNS records. To get fully-resolved services instead, use `async_browse`.

Must only be called once per lifetime. Cannot be combined with `async_browse` on the same instance.

### async_browse

```cpp
void async_browse(std::string_view service_type,
                  std::move_only_function<void(std::error_code, std::vector<resolved_service>)> on_done);
```

Higher-level alternative to `async_discover`. Sends the same PTR query, but internally calls [`aggregate()`](resolved_service.md) on the collected records at the silence timeout, delivering fully-resolved [`resolved_service`](resolved_service.md) values with hostname, port, addresses, and TXT entries already correlated.

Must only be called once per lifetime. Cannot be combined with `async_discover` on the same instance.

### stop

```cpp
void stop();
```

Stops the active receive loop(s) and fires the corresponding completion handler with results accumulated so far. If `async_browse` was used, `aggregate()` is called on the raw records before invoking the handler.

### results

```cpp
const std::vector<mdns_record_variant>& results() const noexcept;
```

Returns accumulated raw records. Populated during either `async_discover` or `async_browse`.

### services

```cpp
const std::vector<resolved_service>& services() const noexcept;
```

Returns aggregated resolved services produced by `async_browse`. Empty until browse completes (either via silence timeout or `stop()`).

### Accessors

```cpp
const socket_type& socket() const noexcept;
      socket_type& socket()       noexcept;
const timer_type&  timer()  const noexcept;
      timer_type&  timer()        noexcept;
```

## async_discover vs async_browse

| | `async_discover` | `async_browse` |
|-|------------------|----------------|
| **Returns** | `std::vector<mdns_record_variant>` | `std::vector<resolved_service>` |
| **Aggregation** | Manual -- call `aggregate()` yourself | Automatic -- handled internally |
| **Use when** | You need raw DNS records | You want service details ready to use |

## Usage Example

### Using async_browse (recommended)

```cpp
// Discover HTTP services and print resolved details.

#include <mdnspp/defaults.h>
#include <mdnspp/resolved_service.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::service_discovery sd{ctx, std::chrono::seconds(3)};

    sd.async_browse("_http._tcp.local.",
        [&ctx](std::error_code ec, std::vector<mdnspp::resolved_service> services)
        {
            if (ec)
            {
                std::cerr << "browse error: " << ec.message() << "\n";
            }
            else
            {
                std::cout << "Found " << services.size() << " service(s):\n";
                for (const auto& svc : services)
                    std::cout << "  " << svc.instance_name
                              << " at " << svc.hostname << ":" << svc.port << "\n";
            }

            ctx.stop();  // ctx.stop() ends ctx.run()
        });

    ctx.run();
}
```

### Using async_discover (raw records)

```cpp
// Discover HTTP services and manually aggregate records.

#include <mdnspp/defaults.h>
#include <mdnspp/records.h>
#include <mdnspp/resolved_service.h>

#include <iostream>
#include <variant>

int main()
{
    mdnspp::context ctx;

    mdnspp::service_discovery sd{ctx, std::chrono::seconds(3),
        [](const mdnspp::mdns_record_variant& rec, mdnspp::endpoint sender)
        {
            std::visit([&](const auto& r) {
                std::cout << sender << " -> " << r << "\n";
            }, rec);
        }
    };

    sd.async_discover("_http._tcp.local.",
        [&ctx](std::error_code ec, std::vector<mdnspp::mdns_record_variant> results)
        {
            if (!ec)
            {
                auto services = mdnspp::aggregate(results);
                std::cout << "Resolved " << services.size() << " service(s) from "
                          << results.size() << " raw record(s)\n";
            }

            ctx.stop();  // ctx.stop() ends ctx.run()
        });

    ctx.run();
}
```

## See Also

- [resolved_service](resolved_service.md) -- the aggregated service type and `aggregate()` function
- [querier](querier.md) -- lower-level query for any record type
- [observer](observer.md) -- passively listen to all mDNS traffic
- [service_server](service_server.md) -- announce a service
