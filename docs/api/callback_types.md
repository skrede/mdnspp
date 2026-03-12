# callback_types

## Overview

Centralized type aliases for all callback and completion handler signatures
used across the mdnspp public API. Each alias wraps a move-only function
type so that callbacks can hold non-copyable captures (unique pointers,
move-only timers, etc.).

**Header:**

```cpp
#include <mdnspp/callback_types.h>
```

Included transitively by every `basic_*` header and both options headers.

## Types

```cpp
namespace mdnspp {

using record_callback = detail::move_only_function<
    void(const endpoint &, const mdns_record_variant &)>;

using error_handler = detail::move_only_function<
    void(std::error_code, std::string_view)>;

using querier_completion_handler = detail::move_only_function<
    void(std::error_code, std::vector<mdns_record_variant>)>;

using observer_completion_handler = detail::move_only_function<
    void(std::error_code)>;

using discovery_completion_handler = detail::move_only_function<
    void(std::error_code, const std::vector<mdns_record_variant> &)>;

using server_completion_handler = detail::move_only_function<
    void(std::error_code)>;

using monitor_completion_handler = detail::move_only_function<
    void(std::error_code)>;

}
```

## Reference

| Type | Signature | Used by |
|------|-----------|---------|
| `record_callback` | `void(const endpoint &, const mdns_record_variant &)` | `query_options`, `observer_options` |
| `error_handler` | `void(std::error_code, std::string_view)` | `basic_service_server` |
| `querier_completion_handler` | `void(std::error_code, std::vector<mdns_record_variant>)` | `basic_querier::async_query` |
| `observer_completion_handler` | `void(std::error_code)` | `basic_observer::async_observe` |
| `discovery_completion_handler` | `void(std::error_code, const std::vector<mdns_record_variant> &)` | `basic_service_discovery::async_discover` |
| `server_completion_handler` | `void(std::error_code)` | `basic_service_server::async_start` |
| `monitor_completion_handler` | `void(std::error_code)` | `basic_service_monitor::async_start` |

### record_callback

Invoked per record as results arrive during a query or observation. The
endpoint identifies the sender; the variant holds the parsed DNS record.

```cpp
mdnspp::query_options opts{
    .on_record = [](const mdnspp::endpoint &sender,
                    const mdnspp::mdns_record_variant &rec)
    {
        std::visit([&](const auto &r) {
            std::cout << sender << " -> " << r << "\n";
        }, rec);
    }
};
```

### error_handler

Invoked on fire-and-forget send failures (e.g., multicast announce errors).
The error code describes the failure; the string view provides context.

```cpp
mdnspp::service_options opts{
    .on_error = [](std::error_code ec, std::string_view context) {
        std::cerr << context << ": " << ec.message() << "\n";
    }
};
```

### Completion handlers

Each class has a dedicated completion handler type. They all receive at
least an `std::error_code`; the querier and discovery variants also receive
the accumulated result set.

```cpp
// Querier -- receives accumulated results
q.async_query("_http._tcp.local.", mdnspp::dns_type::ptr,
    [](std::error_code ec, std::vector<mdnspp::mdns_record_variant> results) {
        std::cout << results.size() << " record(s)\n";
    });

// Observer -- error code only
o.async_observe("_http._tcp.local.", mdnspp::dns_type::ptr,
    [](std::error_code ec) {
        std::cout << "observation stopped: " << ec.message() << "\n";
    });
```

## See Also

- [querier](querier.md) -- uses `querier_completion_handler` and `record_callback`
- [observer](observer.md) -- uses `observer_completion_handler` and `record_callback`
- [service_discovery](service_discovery.md) -- uses `discovery_completion_handler`
- [service_server](service_server.md) -- uses `server_completion_handler` and `error_handler`
- [service_monitor](service_monitor.md) -- uses `monitor_completion_handler`
- [query_options](query_options.md) -- options struct using `record_callback`
- [observer_options](observer_options.md) -- options struct using `record_callback`
