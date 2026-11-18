# observer

Listens for mDNS multicast traffic on the local network and delivers each parsed DNS record to a user-provided callback. No queries are sent &mdash; `basic_observer` is a pure listener. Unlike the record-consuming peers (querier, discovery, monitor), the observer performs no QR-flag or section filtering: records carried in query packets (known-answer lists, probe proposals) are delivered too, with the sender endpoint. Malformed packets are silently skipped.

## Header and Alias

| Form | Header |
|------|--------|
| `basic_observer<P>` | `#include <mdnspp/basic_observer.h>` |
| `mdnspp::observer` (default_policy alias) | `#include <mdnspp/defaults.h>` |

```cpp
// Template form
template <policy_like P>
class basic_observer;

// default_policy alias (from defaults.h)
using observer = basic_observer<default_policy>;
```

## Template Parameters

| Parameter | Constraint | Description |
|-----------|------------|-------------|
| `P` | satisfies `policy_like` | Provides `executor_type`, `socket_type`, and `timer_type`. See [policies](../policies.md). |

## Type Aliases

```cpp
using executor_type = typename P::executor_type;
using socket_type   = typename P::socket_type;
using timer_type    = typename P::timer_type;
```

Callback types are defined in `<mdnspp/callback_types.h>` (included transitively):

```cpp
using record_callback    = mdnspp::record_callback;             // void(const endpoint&, const mdns_record_variant&)
using completion_handler = mdnspp::observer_completion_handler; // void(std::error_code)
using error_handler      = mdnspp::error_handler;               // void(std::error_code, std::string_view)
```

## Constructors

### Throwing

```cpp
explicit basic_observer(executor_type ex,
                        observer_options opts = {},
                        policy_socket_options_t<P> sock_opts = {},
                        mdns_options mdns_opts = {});
```

Constructs the observer from an executor (or context), optional [`observer_options`](observer_options.md) (per-record callback, error handler), optional socket options (network interface, multicast TTL, loopback; type `policy_socket_options_t<P>` — plain `socket_options` for the default and asio policies, the policy's derived options type otherwise), and optional [`mdns_options`](mdns_options.md) (protocol timing tunables). Throws `std::system_error` on socket construction failure (e.g. bind error) or invalid `mdns_options` (`std::errc::invalid_argument`).

### Non-throwing

```cpp
basic_observer(executor_type ex,
               observer_options opts,
               policy_socket_options_t<P> sock_opts,
               mdns_options mdns_opts,
               std::error_code &ec);
```

Same as the throwing constructor, but sets `ec` instead of throwing on failure. All parameters must be provided explicitly (no defaults).

`basic_observer` is non-copyable and non-movable (receive-loop handlers capture `this`).

## Methods

### async_observe

```cpp
void async_observe(completion_handler on_done = {});
```

Arms the internal receive loop and returns immediately. Incoming multicast packets are parsed and each record delivered to the `record_callback`.

Completion semantics:

- The observation has no natural completion; `on_done` fires only when the observation ends — on `stop()` or destruction — with `std::errc::operation_canceled`.
- `async_observe` is one-shot: a second call completes the supplied handler with `std::errc::operation_in_progress`; a call after `stop()` completes it with `std::errc::invalid_argument`. The running observation is unaffected.

### stop

```cpp
void stop();
```

Idempotent and callable from any thread (including from within the `record_callback`). Posts the teardown to the executor; the pending `on_done` fires with `std::errc::operation_canceled`. The destructor calls `stop()` automatically and completes a still-pending handler rather than dropping it.

### Error reporting

Fatal receive errors are reported through the `observer_options::on_error` field (`error_handler`, `void(std::error_code, std::string_view)`). The context string identifies the failure site (e.g. `"receive"`). Without a handler, these errors are silently ignored.

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
                    std::cout << sender << " -> " << r << std::endl;
                }, rec);

                if (++count >= 5)
                    obs.stop();
            }
        }
    };

    obs.async_observe([&ctx](std::error_code) {
        ctx.stop();  // fires with operation_canceled when obs.stop() runs
    });

    ctx.run();
}
```

## See Also

- [observer_options](observer_options.md) &mdash; per-record callback configuration
- [querier](querier.md) &mdash; send a query and collect matching records
- [service_discovery](service_discovery.md) &mdash; discover services by type
- [resolved_service](resolved_service.md) &mdash; aggregated service view
- [Socket Options](../socket-options.md) &mdash; network interface selection, multicast TTL, loopback control
