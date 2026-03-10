# observer

Listens for mDNS multicast traffic on the local network and delivers each parsed DNS record to a user-provided callback. No queries are sent -- `basic_observer` is a pure listener.

## Header and Alias

| Form | Header |
|------|--------|
| `basic_observer<P>` | `#include <mdnspp/basic_observer.h>` |
| `mdnspp::observer` (DefaultPolicy alias) | `#include <mdnspp/defaults.h>` |

```cpp
// Template form
template <Policy P>
class basic_observer;

// DefaultPolicy alias (from defaults.h)
using observer = basic_observer<DefaultPolicy>;
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
using completion_handler = std::move_only_function<void(std::error_code)>;
using error_handler     = detail::move_only_function<void(std::error_code, std::string_view)>;
```

## Constructors

### Throwing

```cpp
explicit basic_observer(executor_type ex,
                        observer_options opts = {},
                        socket_options sock_opts = {});
```

Constructs the observer from an executor (or context), optional [`observer_options`](observer_options.md) (per-record callback), and optional [`socket_options`](../socket-options.md) (network interface, multicast TTL, loopback). Throws on socket construction failure (e.g. bind error).

### Non-throwing

```cpp
basic_observer(executor_type ex,
               observer_options opts,
               socket_options sock_opts,
               std::error_code& ec);
```

Same as the throwing constructor, but sets `ec` instead of throwing on failure. All parameters must be provided explicitly (no defaults).

## Methods

### async_observe

```cpp
void async_observe(completion_handler on_done = {});
```

Arms the internal receive loop and returns immediately. Incoming multicast packets are parsed and each record delivered to the `record_callback`. The `on_done` handler fires with `std::error_code{}` when `stop()` is called.

Must only be called once per lifetime.

### stop

```cpp
void stop();
```

Idempotent. Fires the completion handler with a default-constructed `std::error_code`, then sets the internal stop flag. The receive loop remains alive until the destructor runs, ensuring in-progress callbacks complete safely.

### on_error

```cpp
void on_error(error_handler handler);
```

Sets a handler invoked when a fire-and-forget send operation fails. The handler receives the error code and a context string identifying the send site. Without a handler, send errors are silently ignored.

### Accessors

```cpp
const socket_type& socket() const noexcept;
      socket_type& socket()       noexcept;
const timer_type&  timer()  const noexcept;
      timer_type&  timer()        noexcept;
```

## Supporting Types

### endpoint

```cpp
struct endpoint {
    std::string address;  // "192.168.1.1" or "fe80::1"
    uint16_t port{0};
};
```

Defined in `<mdnspp/endpoint.h>`. Supports three-way comparison and `operator<<`.

### mdns_record_variant

```cpp
using mdns_record_variant = std::variant<
    record_ptr,
    record_srv,
    record_a,
    record_aaaa,
    record_txt
>;
```

Defined in `<mdnspp/records.h>`. Each alternative carries `name`, `ttl`, `rclass`, `length`, `sender_address`, and type-specific fields. All alternatives support `operator<<`.

## Usage Example

```cpp
// Observe mDNS traffic, print the first 5 records, then stop.

#include <mdnspp/defaults.h>
#include <mdnspp/records.h>

#include <iostream>
#include <variant>

int main()
{
    mdnspp::context ctx;
    int count = 0;

    mdnspp::observer obs{ctx,
        mdnspp::observer_options{
            .on_record = [&](const mdnspp::endpoint& sender,
                             const mdnspp::mdns_record_variant& rec)
            {
                std::visit([&](const auto& r) {
                    std::cout << sender << " -> " << r << "\n";
                }, rec);

                if (++count >= 5)
                    obs.stop();
            }
        }
    };

    obs.async_observe([&ctx](std::error_code) {
        ctx.stop();  // ctx.stop() ends ctx.run()
    });

    ctx.run();
}
```

## See Also

- [observer_options](observer_options.md) -- per-record callback configuration
- [querier](querier.md) -- send a query and collect matching records
- [service_discovery](service_discovery.md) -- discover services by type
- [resolved_service](resolved_service.md) -- aggregated service view
- [Socket Options](../socket-options.md) -- network interface selection, multicast TTL, loopback control
