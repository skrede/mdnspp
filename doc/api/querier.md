# querier

Sends a single mDNS query for a given name and record type, then collects matching responses until a silence timeout expires. Results are delivered both per-record (via the optional `record_callback`) and in aggregate (via the `completion_handler`).

For multicast (QM) queries, the querier implements a 20--120 ms random delay before sending (RFC 6762 section 5.2) and duplicate question suppression (RFC 6762 section 7.3) during the delay window. Unicast (QU) queries are sent immediately with no delay.

## Header and Alias

| Form | Header |
|------|--------|
| `basic_querier<P>` | `#include <mdnspp/basic_querier.h>` |
| `mdnspp::querier` (DefaultPolicy alias) | `#include <mdnspp/defaults.h>` |

```cpp
// Template form
template <Policy P>
class basic_querier;

// DefaultPolicy alias (from defaults.h)
using querier = basic_querier<DefaultPolicy>;
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
using completion_handler = std::move_only_function<void(std::error_code, std::vector<mdns_record_variant>)>;
using error_handler     = detail::move_only_function<void(std::error_code, std::string_view)>;
```

## Constructors

### Throwing

```cpp
explicit basic_querier(executor_type ex,
                       std::chrono::milliseconds silence_timeout,
                       socket_options opts = {},
                       record_callback on_record = {});
```

Constructs the querier from an executor, a silence timeout, optional socket options, and an optional per-record callback. The `silence_timeout` determines how long to wait after the last relevant packet before completing. The `opts` parameter controls network interface selection, multicast TTL, and loopback (see [Socket Options](../socket-options.md)). Throws on socket construction failure.

Note: `socket_options` sits between the silence timeout and the callback. To pass a callback without custom socket options, use `q{ex, timeout, {}, callback}`.

### Non-throwing

```cpp
basic_querier(executor_type ex,
              std::chrono::milliseconds silence_timeout,
              socket_options opts,
              record_callback on_record,
              std::error_code& ec);
```

Same as the throwing constructor, but sets `ec` instead of throwing on failure. All parameters must be provided explicitly (no defaults).

## Methods

### async_query

```cpp
void async_query(std::string_view name, dns_type qtype, completion_handler on_done,
                 response_mode mode = response_mode::multicast);
```

Sends a DNS query for `name` with record type `qtype` to the mDNS multicast group (`224.0.0.251:5353`), then listens for responses. The `on_done` handler fires with the accumulated results when the silence timeout expires or `stop()` is called. When `mode` is `response_mode::unicast`, the QU bit (RFC 6762 section 5.4) is set in the outgoing query, requesting a direct unicast response.

Must only be called once per lifetime.

#### QM delay behavior

For multicast (QM) queries, the query is not sent immediately. Instead:

1. The receive loop starts first to listen for traffic.
2. A random delay of 20--120 ms is chosen (RFC 6762 section 5.2).
3. During the delay window, incoming QM queries with a matching name and type are checked for duplicate question suppression (RFC 6762 section 7.3).
4. If a duplicate is detected, the outgoing query is suppressed entirely -- another host has already asked the same question.
5. If no duplicate is seen, the query is sent after the delay expires.

For unicast (QU) queries, the query is sent immediately with no delay and no duplicate suppression.

### stop

```cpp
void stop();
```

Cancels the delay timer and stops the receive loop. Fires the completion handler with the results accumulated so far.

### on_error

```cpp
void on_error(error_handler handler);
```

Sets a handler invoked when a fire-and-forget send operation fails. The handler receives the error code and a context string identifying the send site (e.g. `"query send"`). Without a handler, send errors are silently ignored.

### results

```cpp
const std::vector<mdns_record_variant>& results() const noexcept;
```

Returns a reference to the accumulated results. Remains valid after completion -- the completion handler receives a copy.

### Accessors

```cpp
const socket_type& socket()      const noexcept;
      socket_type& socket()            noexcept;
const timer_type&  timer()       const noexcept;
      timer_type&  timer()             noexcept;
const timer_type&  delay_timer() const noexcept;
      timer_type&  delay_timer()       noexcept;
```

The querier uses two timers: `timer()` for the silence timeout on the receive loop, and `delay_timer()` for the 20--120 ms QM delay before sending.

## Supporting Types

### dns_type

```cpp
enum class dns_type : uint16_t {
    none = 0,
    a    = 1,
    ptr  = 12,
    txt  = 16,
    aaaa = 28,
    srv  = 33,
    any  = 255,
};
```

Defined in `<mdnspp/detail/dns_enums.h>`. Use `to_string(dns_type)` for a human-readable label.

### dns_class

```cpp
enum class dns_class : uint16_t {
    none = 0,
    in   = 1,
};
```

Defined in `<mdnspp/detail/dns_enums.h>`. Use `to_string(dns_class)` for a human-readable label.

## Usage Example

```cpp
// Query for _http._tcp.local. PTR records with a 3-second silence timeout.

#include <mdnspp/defaults.h>
#include <mdnspp/records.h>

#include <iostream>
#include <variant>

int main()
{
    mdnspp::context ctx;

    mdnspp::querier q{ctx, std::chrono::seconds(3), {},
        [](const mdnspp::endpoint& sender, const mdnspp::mdns_record_variant& rec)
        {
            std::visit([&](const auto& r) {
                std::cout << sender << " -> " << r << "\n";
            }, rec);
        }
    };

    q.async_query("_http._tcp.local.", mdnspp::dns_type::ptr,
        [&ctx](std::error_code ec, std::vector<mdnspp::mdns_record_variant> results)
        {
            if (ec)
                std::cerr << "query error: " << ec.message() << "\n";
            else
                std::cout << "Query complete -- " << results.size() << " record(s)\n";

            ctx.stop();
        });

    ctx.run();
}
```

## See Also

- [observer](observer.md) -- passively listen to all mDNS traffic
- [service_discovery](service_discovery.md) -- higher-level service browsing
- [resolved_service](resolved_service.md) -- aggregated service view
- [Socket Options](../socket-options.md) -- network interface selection, multicast TTL, loopback control
