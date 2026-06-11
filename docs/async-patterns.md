# Async Patterns

## ASIO primer

If you are new to ASIO, here is a minimal mental model:

- `asio::io_context` is the event loop. Async operations are submitted to it,
  and `io_context::run()` processes them until there is no more work.
- A **completion token** controls how the result of an async operation is
  delivered: as a callback, a `std::future`, a coroutine awaitable, or a
  deferred operation.
- mdnspp's ASIO adapters use `asio::async_initiate`, so all standard
  completion token forms work, including token adapters such as
  `asio::as_tuple` and `asio::cancel_after`.

## Setup

All examples below share this common setup. Configure mdnspp with
`-DMDNSPP_ENABLE_ASIO_POLICY=ON` to build the adapters, then link
`mdnspp::asio` &mdash; the `MDNSPP_ENABLE_ASIO_POLICY` compile definition is
propagated to consumers automatically.

```cmake
target_link_libraries(my_app PRIVATE mdnspp::asio)
```

The ASIO umbrella header pulls in all adapters and the policy:

```cpp
#include <mdnspp/asio.h>
```

## Adapters and completion signatures

| Adapter | Completes | Signature |
|---------|-----------|-----------|
| `mdnspp::async_observe(obs, token)` | on `stop()` (`std::errc::operation_canceled`) | `void(std::error_code)` |
| `mdnspp::async_query(q, name, qtype, token, mode)` | at the silence timeout, or on `stop()` | `void(std::error_code, std::vector<mdns_record_variant>)` |
| `mdnspp::async_discover(sd, service_type, token, mode)` | at the silence timeout, or on `stop()` | `void(std::error_code, std::vector<mdns_record_variant>)` |
| `mdnspp::async_browse(sd, service_type, token, mode)` | at the silence timeout, or on `stop()` | `void(std::error_code, std::vector<resolved_service>)` |
| `mdnspp::async_start(srv, token)` | when the server is **ready** (probed and announced), or on startup failure | `void(std::error_code)` |
| `mdnspp::async_run(srv, token)` | after `stop()` has run the full **teardown** (run-until-stopped) | `void(std::error_code)` |

`mode` is `mdnspp::response_mode` and defaults to
`mdnspp::response_mode::multicast`.

All adapters accept any completion token satisfying
`asio::completion_token_for` with the corresponding signature.

## Error codes: stop versus natural completion

The first completion argument is always a `std::error_code` and
distinguishes how the operation ended:

- **Natural completion** &mdash; `std::error_code{}`. A query, discovery, or
  browse completes this way at the silence timeout
  (`mdnspp::query_options::silence_timeout`, default 3000 ms), carrying the
  accumulated results.
- **`stop()` before natural completion** &mdash; `std::errc::operation_canceled`,
  carrying the partial results accumulated so far. An observation has no
  natural completion, so `operation_canceled` is its normal completion path.
- **One-shot misuse** &mdash; each peer supports exactly one operation per
  lifetime (see below): a second start completes the *new* token with
  `std::errc::operation_in_progress`; a start after `stop()` completes with
  `std::errc::invalid_argument`. The running operation is unaffected.

With throwing tokens (`asio::use_future`, `asio::use_awaitable`) a non-zero
`std::error_code` becomes a thrown `std::system_error`. Wrap the token in
`asio::as_tuple(...)` to receive the `std::error_code` as a value instead.

## One operation per peer lifetime

Peers (`mdnspp::basic_observer<P>`, `mdnspp::basic_querier<P>`,
`mdnspp::basic_service_discovery<P>`, `mdnspp::basic_service_server<P>`) are
non-copyable, non-movable, and one-shot: construct a peer, run exactly one
asynchronous operation on it, and construct a new peer for the next
operation. A peer must outlive its operation; destroying a peer with a
pending handler completes that handler with
`std::errc::operation_canceled`.

Consequently `async_start` and `async_run` are alternatives, not a
sequence: both call the server's `async_start()` internally, and a server
can be started only once.

## Executor and threading contract

The adapters target `mdnspp::asio_policy`, whose `executor_type` is
`asio::io_context &`. All peer callbacks and completion handlers execute on
the thread that runs the `asio::io_context`; the library assumes a
single-threaded `io_context::run()` and does not serialize callbacks for
multi-threaded `run()`. `stop()` is the exception: it is idempotent and may
be called from any thread (it sets an atomic flag and posts the teardown to
the executor).

Completion handlers are dispatched onto their associated executor with the
associated allocator; the adapters hold an
`asio::executor_work_guard` for the handler's executor until the handler has
run.

## Cancellation

Every adapter honors the completion handler's associated cancellation slot
(`asio::associated_cancellation_slot`). A requested cancellation of any
`asio::cancellation_type_t` calls the peer's `stop()`, so token adapters
such as `asio::cancel_after`, `asio::experimental::awaitable_operators`
(`||`), and `asio::experimental::make_parallel_group` work as expected. The
operation then completes through the peer's own stop semantics:

- observe / query / discover / browse: `std::errc::operation_canceled` with
  partial results,
- `async_start`: `std::errc::operation_canceled` (the server was stopped
  before becoming live),
- `async_run`: `std::error_code{}` &mdash; cancellation requests a stop, and the
  token completes after the resulting teardown, which is the operation's
  successful outcome.

Bounding a discovery with `asio::cancel_after`:

```cpp
#include <mdnspp/asio.h>
#include <mdnspp/basic_service_discovery.h>
#include <mdnspp/records.h>

#include <asio/cancel_after.hpp>

#include <chrono>
#include <iostream>
#include <variant>

asio::awaitable<void> discover(asio::io_context &io)
{
    mdnspp::basic_service_discovery<mdnspp::asio_policy> sd{io};

    auto [ec, results] = co_await mdnspp::async_discover(
        sd, "_http._tcp.local.",
        asio::cancel_after(std::chrono::seconds(2),
                           asio::as_tuple(asio::use_awaitable)));

    if(ec == std::errc::operation_canceled)
        std::cout << "deadline reached -- " << results.size()
            << " record(s) so far" << std::endl;
    else
        std::cout << "discovered " << results.size() << " record(s)" << std::endl;
}

int main()
{
    asio::io_context io;
    asio::co_spawn(io, discover(io), asio::detached);
    io.run();
}
```

Racing an operation against a timer with awaitable operators works the same
way &mdash; the loser is cancelled through its slot:

```cpp
using namespace asio::experimental::awaitable_operators;

asio::steady_timer deadline{io, std::chrono::seconds(2)};
auto winner = co_await (mdnspp::async_observe(obs, asio::use_awaitable)
                        || deadline.async_wait(asio::use_awaitable));
```

A cancellation that arrives after the operation has completed has no
effect: the slot is cleared before the completion handler is invoked.

## Server startup: async_start versus async_run

`mdnspp::async_start(srv, token)` binds the server's *ready* event. It
completes with:

- `std::error_code{}` once the probe &rarr; announce sequence finishes and the
  server is live. The server keeps serving after completion; end it with
  `srv.stop()`.
- `mdnspp::mdns_error::probe_conflict` on an unresolvable name conflict. The
  full teardown has already run; the server is defunct.
- `std::errc::invalid_argument` on an unencodable name or reuse after
  `stop()`; `std::errc::operation_in_progress` on a double start.
- `std::errc::operation_canceled` when `srv.stop()` is called before the
  server becomes live.

`mdnspp::async_run(srv, token)` starts the server and completes on the
first of the server's *done* event and a *ready* event whose code implies
the done event can never fire. It completes with `std::error_code{}` after
`srv.stop()` has run the full teardown (goodbye packets included) and on an
unresolvable probe conflict, because the teardown runs and the done event
fires on that path as well &mdash; observe the startup outcome with
`async_start` (or the core `async_start(on_ready, on_done)` callback API)
when it is needed. It completes with `std::errc::invalid_argument` on an
unencodable name (the ready event delivers the reason ahead of the
teardown's done event and wins the exactly-once completion) and on the
misuse paths, where the done event never fires: `std::errc::invalid_argument`
after `stop()`, `std::errc::operation_in_progress` on a double start.

```cpp
#include <mdnspp/asio.h>
#include <mdnspp/basic_service_server.h>
#include <mdnspp/service_info.h>

#include <iostream>

int main()
{
    asio::io_context io;

    mdnspp::service_info info{
        .service_name = "MyApp._http._tcp.local.",
        .service_type = "_http._tcp.local.",
        .hostname     = "myhost.local.",
        .port         = 8080,
        .address_ipv4 = "192.168.1.69",
        .txt_records  = {{"path", "/index.html"}},
    };

    mdnspp::basic_service_server<mdnspp::asio_policy> srv{io, std::move(info)};
    asio::steady_timer stop_timer(io);

    mdnspp::async_start(srv, [&stop_timer, &srv](std::error_code ec)
    {
        if(ec)
        {
            std::cerr << "startup failed: " << ec.message() << std::endl;
            return;
        }
        std::cout << "service live -- stopping in 10 seconds" << std::endl;
        stop_timer.expires_after(std::chrono::seconds(10));
        stop_timer.async_wait([&srv](std::error_code) { srv.stop(); });
    });

    io.run(); // returns after the teardown drains the event loop
}
```

## Completion tokens

### Callback

Pass a lambda (or any callable) directly as the completion token.

```cpp
#include <mdnspp/asio.h>
#include <mdnspp/basic_observer.h>
#include <mdnspp/records.h>

#include <iostream>
#include <variant>

int main()
{
    asio::io_context io;

    mdnspp::basic_observer<mdnspp::asio_policy> obs{io,
        mdnspp::observer_options{
            .on_record = [](const mdnspp::endpoint &sender,
                            const mdnspp::mdns_record_variant &rec)
            {
                std::visit([&](const auto &r) {
                    std::cout << sender.address << ":" << sender.port
                        << " -> " << r << std::endl;
                }, rec);
            }
        }
    };

    mdnspp::async_observe(obs,
        [](std::error_code ec)
        {
            if (ec == std::errc::operation_canceled)
                std::cout << "observation stopped" << std::endl;
            else if (ec)
                std::cerr << "observe error: " << ec.message() << std::endl;
        });

    asio::steady_timer stop_timer(io, std::chrono::seconds(30));
    stop_timer.async_wait([&obs](std::error_code) { obs.stop(); });

    io.run();
}
```

### use_future

Pass `asio::use_future` to get a `std::future` back. The future throws
`std::system_error` if the operation completes with a non-zero
`std::error_code`.

```cpp
#include <mdnspp/asio.h>
#include <mdnspp/basic_querier.h>
#include <mdnspp/records.h>

#include <future>
#include <iostream>
#include <variant>

int main()
{
    asio::io_context io;

    mdnspp::basic_querier<mdnspp::asio_policy> q{io};

    std::future<std::vector<mdnspp::mdns_record_variant>> fut =
        mdnspp::async_query(q, "_http._tcp.local.", mdnspp::dns_type::ptr,
                            asio::use_future);

    io.run();

    try
    {
        auto results = fut.get();
        std::cout << "query complete -- " << results.size()
            << " record(s)" << std::endl;
        for (const auto &rec : results)
            std::visit([](const auto &r) { std::cout << "  " << r << std::endl; }, rec);
    }
    catch (const std::system_error &e)
    {
        std::cerr << "query error: " << e.what() << std::endl;
    }
}
```

### use_awaitable

Pass `asio::use_awaitable` inside a coroutine to `co_await` the result.
Spawn the coroutine with `asio::co_spawn`. Errors throw `std::system_error`
from the `co_await` expression; combine with `asio::as_tuple` to receive the
`std::error_code` as a value (see the cancellation example above). Requires
compiler coroutine support (GCC 13+, Clang 18+, MSVC 17+).

```cpp
#include <mdnspp/asio.h>
#include <mdnspp/basic_service_discovery.h>
#include <mdnspp/records.h>

#include <iostream>
#include <variant>

asio::awaitable<void> discover(asio::io_context &io)
{
    mdnspp::basic_service_discovery<mdnspp::asio_policy> sd{io};

    auto results = co_await mdnspp::async_discover(
        sd, "_http._tcp.local.", asio::use_awaitable);

    std::cout << "discovered " << results.size() << " record(s)" << std::endl;
    for (const auto &rec : results)
        std::visit([](const auto &r) { std::cout << "  " << r << std::endl; }, rec);
}

int main()
{
    asio::io_context io;
    asio::co_spawn(io, discover(io), asio::detached);
    io.run();
}
```

### deferred

Pass `asio::deferred` to get a deferred operation that initiates no I/O
until it is invoked with a handler (or `co_await`ed).

```cpp
#include <mdnspp/asio.h>
#include <mdnspp/basic_service_discovery.h>
#include <mdnspp/records.h>

#include <iostream>
#include <vector>

int main()
{
    asio::io_context io;

    mdnspp::basic_service_discovery<mdnspp::asio_policy> sd{io};

    auto op = mdnspp::async_discover(sd, "_http._tcp.local.", asio::deferred);

    // I/O initiates here, when the deferred operation is launched.
    std::move(op)(
        [](std::error_code ec, std::vector<mdnspp::mdns_record_variant> results)
        {
            if (ec)
                std::cerr << "discovery error: " << ec.message() << std::endl;
            else
                std::cout << "discovered " << results.size()
                    << " record(s)" << std::endl;
        });

    io.run();
}
```

## Next steps

- [Policies](policies.md) &mdash; understand the policy architecture
- [API Reference](api/) &mdash; full type documentation
