# querier

Sends a single mDNS query for a given name and record type, then collects matching responses until a silence timeout expires. Results are delivered both per-record (via the optional `record_callback`) and in aggregate (via the `completion_handler`).

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
```

## Constructors

### Throwing

```cpp
explicit basic_querier(executor_type ex,
                       std::chrono::milliseconds silence_timeout,
                       record_callback on_record = {});
```

Constructs the querier from an executor, a silence timeout, and an optional per-record callback. The `silence_timeout` determines how long to wait after the last relevant packet before completing. Throws on socket construction failure.

### Non-throwing

```cpp
basic_querier(executor_type ex,
              std::chrono::milliseconds silence_timeout,
              record_callback on_record,
              std::error_code& ec);

basic_querier(executor_type ex,
              std::chrono::milliseconds silence_timeout,
              std::error_code& ec);
```

Same as the throwing constructor, but sets `ec` instead of throwing on failure.

## Methods

### async_query

```cpp
void async_query(std::string_view name, dns_type qtype, completion_handler on_done);
```

Sends a DNS query for `name` with record type `qtype` to the mDNS multicast group (`224.0.0.251:5353`), then listens for responses. The `on_done` handler fires with the accumulated results when the silence timeout expires or `stop()` is called.

Must only be called once per lifetime.

### stop

```cpp
void stop();
```

Stops the receive loop early and fires the completion handler with the results accumulated so far.

### results

```cpp
const std::vector<mdns_record_variant>& results() const noexcept;
```

Returns a reference to the accumulated results. Remains valid after completion -- the completion handler receives a copy.

### Accessors

```cpp
const socket_type& socket() const noexcept;
      socket_type& socket()       noexcept;
const timer_type&  timer()  const noexcept;
      timer_type&  timer()        noexcept;
```

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

    mdnspp::querier q{ctx, std::chrono::seconds(3),
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

            ctx.stop();  // ctx.stop() ends ctx.run()
        });

    ctx.run();
}
```

## See Also

- [observer](observer.md) -- passively listen to all mDNS traffic
- [service_discovery](service_discovery.md) -- higher-level service browsing
- [resolved_service](resolved_service.md) -- aggregated service view
