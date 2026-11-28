# callback_types

## Overview

Centralized type aliases for all callback and completion handler signatures
used across the mdnspp public API. Each alias wraps
`mdnspp::move_only_function` so that callbacks can hold non-copyable
captures (unique pointers, move-only timers, etc.).

**Header:**

```cpp
#include <mdnspp/callback_types.h>
```

Included transitively by every `basic_*` header and the options headers.

## Types

```cpp
namespace mdnspp {

/// Callback invoked per record as results arrive during a query or observation.
using record_callback = move_only_function<void(const endpoint &, const mdns_record_variant &)>;

/// Error handler invoked on fire-and-forget send failures and fatal receive errors.
using error_handler = move_only_function<void(std::error_code, std::string_view)>;

/// Completion handler for basic_querier.
using querier_completion_handler = move_only_function<void(std::error_code, std::vector<mdns_record_variant>)>;

/// Completion handler for basic_observer.
using observer_completion_handler = move_only_function<void(std::error_code)>;

/// Completion handler for basic_service_discovery::async_discover.
using discovery_completion_handler = move_only_function<void(std::error_code, std::vector<mdns_record_variant>)>;

/// Completion handler for basic_service_discovery::async_browse.
using browse_completion_handler = move_only_function<void(std::error_code, std::vector<resolved_service>)>;

/// Completion handler for basic_service_server.
using server_completion_handler = move_only_function<void(std::error_code)>;

/// Completion handler for basic_service_monitor.
using monitor_completion_handler = move_only_function<void(std::error_code)>;

}
```

## Reference

| Type | Signature | Used by |
|------|-----------|---------|
| `record_callback` | `void(const endpoint &, const mdns_record_variant &)` | `query_options::on_record`, `observer_options::on_record` |
| `error_handler` | `void(std::error_code, std::string_view)` | `service_options::on_error`, `monitor_options::on_error`, `query_options::on_error`, `observer_options::on_error` |
| `querier_completion_handler` | `void(std::error_code, std::vector<mdns_record_variant>)` | `basic_querier::async_query` |
| `observer_completion_handler` | `void(std::error_code)` | `basic_observer::async_observe` |
| `discovery_completion_handler` | `void(std::error_code, std::vector<mdns_record_variant>)` | `basic_service_discovery::async_discover` |
| `browse_completion_handler` | `void(std::error_code, std::vector<resolved_service>)` | `basic_service_discovery::async_browse` |
| `server_completion_handler` | `void(std::error_code)` | `basic_service_server::async_start` (`on_ready` and `on_done`) |
| `monitor_completion_handler` | `void(std::error_code)` | `basic_service_monitor::async_start` |

## Threading, re-entrancy, and lifetime contract

These rules apply to every callback and completion handler in the library:

- **Executor affinity.** All callbacks fire on the policy executor — the
  thread driving `ctx.run()` (default policy), `io.run()` (asio policy), or
  `executor.run()` (inproc policy). The library never invokes a callback
  while holding an internal lock; serialization is provided by the executor.
- **Re-entrancy.** A callback may call `stop()` on its own peer; `stop()` is
  idempotent and posts the teardown rather than running it inline.
- **Lifetime.** A peer must NOT be destroyed from within one of its own
  callbacks. Destroy peers from outside the callback chain (e.g. after
  `run()` returns, or from the completion handler of a different peer).
- **No silent drops.** `stop()` and destruction complete pending completion
  handlers with `std::errc::operation_canceled` (the querier and discovery
  variants additionally deliver the partial results accumulated so far; the
  monitor's `on_done` completes with `std::error_code{}` on `stop()`, which
  is its natural completion). A handler passed to an `async_*` initiating
  function therefore always fires exactly once.
- **One-shot misuse.** Starting a second operation on a one-shot peer
  completes the supplied handler with `std::errc::operation_in_progress`;
  starting after `stop()` completes it with `std::errc::invalid_argument`.
  The running operation is unaffected. See [Errors](errors.md).
- **Blocking.** Do not block inside callbacks: the executor thread also
  drives socket receives and timers for every peer sharing it.

### record_callback

Invoked per record as results arrive during a query or observation. The
endpoint identifies the sender; the variant holds the parsed DNS record.

```cpp
mdnspp::query_options opts{
    .on_record = [](const mdnspp::endpoint &sender,
                    const mdnspp::mdns_record_variant &rec)
    {
        std::visit([&](const auto &r) {
            std::cout << sender << " -> " << r << std::endl;
        }, rec);
    }
};
```

### error_handler

Invoked on fire-and-forget send failures (e.g. multicast announce errors)
and fatal receive errors. The error code describes the failure; the string
view provides context identifying the failure site (e.g. `"probe send"`,
`"receive"`). `on_error` is a field of the per-peer options structs:
`service_options`, `monitor_options`, `query_options`, and
`observer_options`.

```cpp
mdnspp::service_options opts{
    .on_error = [](std::error_code ec, std::string_view context) {
        std::cerr << context << ": " << ec.message() << std::endl;
    }
};
```

### Completion handlers

Each class has a dedicated completion handler type. They all receive at
least a `std::error_code`; the querier, discovery, and browse variants also
receive the accumulated result set by value.

```cpp
// Querier -- receives accumulated results
q.async_query("_http._tcp.local.", mdnspp::dns_type::ptr,
    [](std::error_code ec, std::vector<mdnspp::mdns_record_variant> results) {
        std::cout << results.size() << " record(s)" << std::endl;
    });

// Observer -- error code only; fires with operation_canceled on stop()
o.async_observe([](std::error_code ec) {
    std::cout << "observation stopped: " << ec.message() << std::endl;
});
```

## See Also

- [Errors](errors.md) -- mdns_error enum and error_code conventions
- [querier](querier.md) &mdash; uses `querier_completion_handler` and `record_callback`
- [observer](observer.md) -- uses `observer_completion_handler` and `record_callback`
- [service_discovery](service_discovery.md) -- uses `discovery_completion_handler` and `browse_completion_handler`
- [service_server](service_server.md) -- uses `server_completion_handler` and `error_handler`
- [service_monitor](service_monitor.md) -- uses `monitor_completion_handler`
- [query_options](query_options.md) -- options struct using `record_callback` and `error_handler`
- [observer_options](observer_options.md) -- options struct using `record_callback` and `error_handler`
