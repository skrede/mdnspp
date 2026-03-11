# service_discovery

Discovers mDNS services by type on the local network. Offers three levels of abstraction: `async_discover` returns raw DNS records, `async_browse` returns fully-resolved [`resolved_service`](resolved_service.md) values, and `async_enumerate_types` returns the available service types on the network. Subtype-filtered discovery is supported via `async_discover_subtype`.

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
using record_callback    = std::move_only_function<void(const endpoint&, const mdns_record_variant&)>;
using completion_handler = std::move_only_function<void(std::error_code, const std::vector<mdns_record_variant>&)>;
using enumerate_handler  = std::move_only_function<void(std::error_code, std::vector<service_type_info>)>;
using error_handler     = detail::move_only_function<void(std::error_code, std::string_view)>;
```

## Constructors

### Throwing

```cpp
explicit basic_service_discovery(executor_type ex,
                                 query_options opts = {},
                                 socket_options sock_opts = {},
                                 mdns_options mdns_opts = {});
```

Constructs the service discovery from an executor, optional [`query_options`](query_options.md) (per-record callback and silence timeout), optional [`socket_options`](../socket-options.md) (network interface, multicast TTL, loopback), and optional [`mdns_options`](mdns_options.md) (query backoff, TTL refresh tunables). All options default to sensible values -- construct with just an executor for a 3-second silence timeout and no per-record callback. Throws on socket construction failure.

### Non-throwing

```cpp
basic_service_discovery(executor_type ex,
                        query_options opts,
                        socket_options sock_opts,
                        mdns_options mdns_opts,
                        std::error_code &ec);
```

Same as the throwing constructor, but sets `ec` instead of throwing on failure. All parameters must be provided explicitly (no defaults).

## Methods

### async_discover

```cpp
void async_discover(std::string_view service_type, completion_handler on_done,
                    response_mode mode = response_mode::multicast);
```

Sends a PTR query for `service_type` to the mDNS multicast group and collects **raw DNS records** until the silence timeout expires. The `on_done` handler receives all accumulated records (PTR, SRV, A, AAAA, TXT) as a flat vector. Includes known answers from previous results per RFC 6762 section 7.1. When `mode` is `response_mode::unicast`, the QU bit (RFC 6762 section 5.4) is set in the outgoing query.

Use this when you need access to individual DNS records. To get fully-resolved services instead, use `async_browse`.

Must only be called once per lifetime. Cannot be combined with `async_browse` on the same instance.

### async_browse

```cpp
void async_browse(std::string_view service_type,
                  std::move_only_function<void(std::error_code, std::vector<resolved_service>)> on_done,
                  response_mode mode = response_mode::multicast);
```

Higher-level alternative to `async_discover`. Sends the same PTR query, but internally calls [`aggregate()`](resolved_service.md) on the collected records at the silence timeout, delivering fully-resolved [`resolved_service`](resolved_service.md) values with hostname, port, addresses, and TXT entries already correlated. When `mode` is `response_mode::unicast`, the QU bit (RFC 6762 section 5.4) is set in the outgoing query.

Must only be called once per lifetime. Cannot be combined with `async_discover` on the same instance.

### async_enumerate_types

```cpp
void async_enumerate_types(enumerate_handler on_done,
                           response_mode mode = response_mode::multicast);
```

DNS-SD service type enumeration (RFC 6763 section 9). Queries `_services._dns-sd._udp.local.` and collects PTR responses until the silence timeout expires. Each PTR response is parsed into a [`service_type_info`](#service_type_info) value. The `on_done` handler receives the complete list of discovered service types.

Must only be called once per lifetime. Uses a dedicated internal receive loop separate from `async_discover` and `async_browse`.

```cpp
mdnspp::context ctx;
mdnspp::service_discovery sd{ctx};

sd.async_enumerate_types(
    [&ctx](std::error_code ec, std::vector<mdnspp::service_type_info> types)
    {
        if (!ec)
        {
            for (const auto &t : types)
                std::cout << t.type_name << "." << t.protocol << " (" << t.domain << ")\n";
        }
        ctx.stop();
    });

ctx.run();
```

### async_discover_subtype

```cpp
void async_discover_subtype(std::string_view service_type,
                            std::string_view subtype_label,
                            completion_handler on_done,
                            response_mode mode = response_mode::multicast);
```

Subtype-filtered discovery (RFC 6763 section 7.1). Constructs the subtype query name `_subtype._sub._service._tcp.local.` and delegates to `async_discover`. The `on_done` handler receives raw DNS records matching the subtype.

```cpp
mdnspp::context ctx;
mdnspp::service_discovery sd{ctx};

sd.async_discover_subtype("_http._tcp.local.", "_printer",
    [&ctx](std::error_code ec, const std::vector<mdnspp::mdns_record_variant> &results)
    {
        if (!ec)
            std::cout << "Found " << results.size() << " subtype records\n";
        ctx.stop();
    });

ctx.run();
```

### stop

```cpp
void stop();
```

Stops all active receive loops and fires the corresponding completion handlers with results accumulated so far. If `async_browse` was used, `aggregate()` is called on the raw records before invoking the handler. If `async_enumerate_types` was used, the enumerated types collected so far are delivered.

### on_error

```cpp
void on_error(error_handler handler);
```

Sets a handler invoked when a fire-and-forget send operation fails. The handler receives the error code and a context string identifying the send site (e.g. `"discover send"`). Without a handler, send errors are silently ignored.

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

## Supporting Types

### service_type_info

```cpp
struct service_type_info
{
    std::string service_type; // full: "_http._tcp.local"
    std::string type_name;    // "_http"
    std::string protocol;     // "_tcp"
    std::string domain;       // "local"
};
```

Defined in `<mdnspp/service_type.h>` (in namespace `mdnspp`), included transitively by `<mdnspp/basic_service_discovery.h>`. Represents a parsed DNS-SD service type name.

### parse_service_type

```cpp
service_type_info parse_service_type(std::string_view name);
```

Free function in namespace `mdnspp`. Decomposes a DNS-SD service type name (e.g. `"_http._tcp.local."`) into its constituent parts: type name, protocol, and domain. Strips trailing dots before parsing.

```cpp
auto info = mdnspp::parse_service_type("_http._tcp.local.");
// info.type_name == "_http"
// info.protocol  == "_tcp"
// info.domain    == "local"
```

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

    mdnspp::service_discovery sd{ctx};

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

            ctx.stop();
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

    mdnspp::service_discovery sd{ctx,
        mdnspp::query_options{
            .on_record = [](const mdnspp::endpoint& sender,
                            const mdnspp::mdns_record_variant& rec)
            {
                std::visit([&](const auto& r) {
                    std::cout << sender << " -> " << r << "\n";
                }, rec);
            }
        }
    };

    sd.async_discover("_http._tcp.local.",
        [&ctx](std::error_code ec, const std::vector<mdnspp::mdns_record_variant> &results)
        {
            if (!ec)
            {
                auto services = mdnspp::aggregate(results);
                std::cout << "Resolved " << services.size() << " service(s) from "
                          << results.size() << " raw record(s)\n";
            }

            ctx.stop();
        });

    ctx.run();
}
```

## See Also

- [query_options](query_options.md) -- per-record callback and silence timeout configuration
- [resolved_service](resolved_service.md) -- the aggregated service type and `aggregate()` function
- [querier](querier.md) -- lower-level query for any record type
- [observer](observer.md) -- passively listen to all mDNS traffic
- [service_server](service_server.md) -- announce a service
- [service_options](service_options.md) -- server lifecycle and behavior control
- [Socket Options](../socket-options.md) -- network interface selection, multicast TTL, loopback control
