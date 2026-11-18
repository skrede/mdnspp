# querier

Sends a single mDNS query for a given name and record type, then collects matching responses until a silence timeout expires. Results are delivered both per-record (via the optional `record_callback`) and in aggregate (via the `completion_handler`).

For multicast (QM) queries, the querier implements a 20--120 ms random delay before sending (RFC 6762 section 5.2) and duplicate question suppression (RFC 6762 section 7.3) during the delay window. Unicast (QU) queries are sent immediately with no delay.

## Header and Alias

| Form | Header |
|------|--------|
| `basic_querier<P>` | `#include <mdnspp/basic_querier.h>` |
| `mdnspp::querier` (default_policy alias) | `#include <mdnspp/defaults.h>` |

```cpp
// Template form
template <policy_like P>
class basic_querier;

// default_policy alias (from defaults.h)
using querier = basic_querier<default_policy>;
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
using record_callback    = mdnspp::record_callback;    // void(const endpoint&, const mdns_record_variant&)
using completion_handler = mdnspp::querier_completion_handler; // void(std::error_code, std::vector<mdns_record_variant>)
using error_handler      = mdnspp::error_handler;      // void(std::error_code, std::string_view)
```

## Constructors

### Throwing

```cpp
explicit basic_querier(executor_type ex,
                       query_options opts = {},
                       policy_socket_options_t<P> sock_opts = {},
                       mdns_options mdns_opts = {});
```

Constructs the querier from an executor, optional [`query_options`](query_options.md) (per-record callback, error handler, and silence timeout), optional socket options (network interface, multicast TTL, loopback; type `policy_socket_options_t<P>` — plain `socket_options` for the default and asio policies), and optional [`mdns_options`](mdns_options.md) (query backoff, TTL refresh tunables). Construct with just an executor for a 3-second silence timeout and no per-record callback. Throws `std::system_error` on socket construction failure or invalid options (`std::errc::invalid_argument`, e.g. non-positive `silence_timeout`).

### Non-throwing

```cpp
basic_querier(executor_type ex,
              query_options opts,
              policy_socket_options_t<P> sock_opts,
              mdns_options mdns_opts,
              std::error_code &ec);
```

Same as the throwing constructor, but sets `ec` instead of throwing on failure. All parameters must be provided explicitly (no defaults).

`basic_querier` is non-copyable and non-movable (receive-loop and timer handlers capture `this`).

## Methods

### async_query

```cpp
void async_query(std::string_view name, dns_type qtype, completion_handler on_done,
                 response_mode mode = response_mode::multicast);
```

Sends a DNS query for `name` with record type `qtype` to the mDNS multicast group (`224.0.0.251:5353`), then listens for responses. Only records carried in response packets (QR=1) are collected. When `mode` is `response_mode::unicast`, the QU bit (RFC 6762 section 5.4) is set in the outgoing query, requesting a direct unicast response.

Completion semantics:

- **Natural completion** (silence timeout elapsed): `on_done` fires with `std::error_code{}` and the accumulated results.
- **`stop()` before natural completion**: `on_done` fires with `std::errc::operation_canceled` and the results accumulated so far.
- **Destruction with a pending operation**: `on_done` is invoked with `std::errc::operation_canceled` before teardown — never silently dropped.
- **Invalid `name`** (failing RFC 1035 §5.1 validation): the handler completes with `mdns_error::invalid_name`; no query is sent.

`async_query` is one-shot: a second call completes the supplied handler with `std::errc::operation_in_progress`; a call after `stop()` completes it with `std::errc::invalid_argument`. The running query is unaffected. Construct a new instance per query.

#### QM delay behavior

For multicast (QM) queries, the query is not sent immediately. Instead:

1. The receive loop starts first to listen for traffic.
2. A random delay of 20--120 ms is chosen (RFC 6762 section 5.2).
3. During the delay window, incoming QM queries with a matching name and type are checked for duplicate question suppression (RFC 6762 section 7.3).
4. If a duplicate is detected, the outgoing query is suppressed entirely &mdash; another host has already asked the same question.
5. If no duplicate is seen, the query is sent after the delay expires.

For unicast (QU) queries, the query is sent immediately with no delay and no duplicate suppression.

### stop

```cpp
void stop();
```

Idempotent; posts teardown to the executor. Cancels the delay timer and stops the receive loop. The completion handler fires with `std::errc::operation_canceled` and the results accumulated so far.

### Error reporting

Fire-and-forget send failures and fatal receive errors are reported through the `query_options::on_error` field (`error_handler`, `void(std::error_code, std::string_view)`). The context string identifies the failure site (e.g. `"query send"`, `"receive"`). Without a handler, these errors are silently ignored.

### results

```cpp
const std::vector<mdns_record_variant>& results() const noexcept;
```

Returns a reference to the accumulated results. Remains valid after completion &mdash; the completion handler receives a copy. The buffer is mutated on the executor thread while the query is in flight; read it only after completion or from the executor thread.

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

    mdnspp::querier q{ctx,
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

- [query_options](query_options.md) &mdash; per-record callback and silence timeout configuration
- [observer](observer.md) &mdash; passively listen to all mDNS traffic
- [service_discovery](service_discovery.md) &mdash; higher-level service browsing
- [resolved_service](resolved_service.md) &mdash; aggregated service view
- [Socket Options](../socket-options.md) &mdash; network interface selection, multicast TTL, loopback control
