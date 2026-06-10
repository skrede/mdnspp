# Errors

How mdnspp reports failures: the `mdns_error` enum, the `std::error_code`
conventions shared by all peers, and where errors surface.

## Header

```cpp
#include <mdnspp/mdns_error.h>
```

Included transitively by every `basic_*` header.

## mdns_error enum

```cpp
namespace mdnspp {

enum class mdns_error : uint32_t
{
    socket_error    = 1,
    no_interfaces   = 2,
    parse_error     = 3,
    send_failed     = 4,
    receive_failed  = 5,
    timeout         = 6,
    not_implemented = 7,
    probe_conflict       = 8,
    invalid_ipv4_address = 9,
    invalid_ipv6_address = 10,
    invalid_name         = 11
};

}
```

`mdns_error` is registered as a `std::error_code` enum
(`std::is_error_code_enum`), so values convert implicitly:

```cpp
std::error_code ec = mdnspp::mdns_error::probe_conflict;
if (ec == mdnspp::mdns_error::probe_conflict) { /* ... */ }
```

The category name is `"mdns"`; `ec.message()` yields a human-readable string
(e.g. `"name conflict detected during probing"`).

| Value | Meaning |
|-------|---------|
| `socket_error` | Socket construction or configuration failed. |
| `no_interfaces` | No usable network interfaces were found. |
| `parse_error` | A DNS message or record could not be parsed. |
| `send_failed` | A send operation failed. |
| `receive_failed` | A receive operation failed. |
| `timeout` | An operation timed out. |
| `not_implemented` | The requested operation is not implemented. |
| `probe_conflict` | RFC 6762 §8/§9 conflict resolution failed permanently; delivered to `basic_service_server`'s `on_ready` handler. |
| `invalid_ipv4_address` | `service_info::address_ipv4` could not be encoded. |
| `invalid_ipv6_address` | `service_info::address_ipv6` could not be encoded. |
| `invalid_name` | A DNS name failed RFC 1035 §5.1 presentation-format validation (bad escape, empty label, label over 63 octets, name over 255 octets). Returned by `dns_name::parse()`, `parse_service_type_checked()`, and the name-taking `async_*` initiating functions. |

## std::error_code conventions

All completion handlers receive a `std::error_code` as their first argument.
The library uses generic `std::errc` values for lifecycle conditions and
`mdns_error` for protocol-specific failures:

| Condition | Error code | Where |
|-----------|------------|-------|
| Natural completion | `std::error_code{}` (falsy) | Querier/discovery at the silence timeout; server `on_ready` when live; server and monitor `on_done` after teardown (stopping is their natural completion). |
| Cancelled by `stop()` or destruction | `std::errc::operation_canceled` | Observer `on_done`; querier/discovery handlers (with the partial results accumulated so far); server `on_ready` when stopped before live. Pending handlers are never silently dropped. |
| One-shot misuse: second start while running | `std::errc::operation_in_progress` | Every `async_*` initiating function; the running operation is unaffected. |
| One-shot misuse: start after `stop()` | `std::errc::invalid_argument` | Every `async_*` initiating function. |
| Invalid options at construction | `std::errc::invalid_argument` | Thrown as `std::system_error` from the throwing constructors; set on `ec` in the non-throwing overloads. Validated fields include positive intervals/TTLs, `probe_count >= 1`, fraction ranges in (0, 1), and non-empty valid service names. |
| Invalid DNS name passed to an initiating function | `mdns_error::invalid_name` | `async_query`, `async_discover`, `async_browse` reject the name up front and complete the handler with this code. |
| Permanent probe conflict | `mdns_error::probe_conflict` | Server `on_ready`; `on_done` then fires with `std::error_code{}` after teardown. |

## Where errors surface

1. **Constructors.** Socket construction failures and invalid options:
   throwing constructors throw `std::system_error`; each peer also provides
   a non-throwing overload with a trailing `std::error_code &ec` (ASIO
   convention).
2. **Completion handlers.** Lifecycle outcomes (success, cancellation,
   misuse, probe conflict) arrive in the handler passed to the `async_*`
   initiating function, on the executor.
3. **`on_error` options fields.** Fire-and-forget send failures and fatal
   receive errors — failures that occur while an operation is running but do
   not terminate it — are reported through the `error_handler on_error{}`
   field of `service_options`, `monitor_options`, `query_options`, and
   `observer_options`. The handler receives the error code and a context
   string identifying the failure site. Without a handler these errors are
   silently ignored.
4. **`expected` returns.** Validation utilities return
   `mdnspp::expected<T, mdns_error>` instead of completing a handler:
   `dns_name::parse()` and `parse_service_type_checked()` return
   `mdns_error::invalid_name` on malformed input. (`mdnspp::expected`
   resolves to `std::expected` when the standard library provides it.)

## Example

```cpp
#include <mdnspp/defaults.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::querier q{ctx, mdnspp::query_options{
        .on_error = [](std::error_code ec, std::string_view context)
        {
            std::cerr << context << ": " << ec.message() << std::endl;
        },
    }};

    q.async_query("_http._tcp.local.", mdnspp::dns_type::ptr,
        [&ctx](std::error_code ec, std::vector<mdnspp::mdns_record_variant> results)
        {
            if (ec == mdnspp::mdns_error::invalid_name)
                std::cerr << "malformed service type" << std::endl;
            else if (ec == std::errc::operation_canceled)
                std::cout << "stopped early with " << results.size() << " record(s)" << std::endl;
            else if (!ec)
                std::cout << "done: " << results.size() << " record(s)" << std::endl;
            ctx.stop();
        });

    ctx.run();
}
```

## See Also

- [callback_types](callback_types.md) -- the threading/re-entrancy/lifetime contract for handlers
- [service_server](service_server.md) -- `on_ready`/`on_done` outcome semantics
- [querier](querier.md), [service_discovery](service_discovery.md), [observer](observer.md) -- per-peer completion semantics
