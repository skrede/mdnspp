# Async Patterns

## ASIO primer

If you are new to ASIO, here is a minimal mental model:

- `asio::io_context` is the event loop. Async operations are submitted to it,
  and `io_context::run()` processes them until there is no more work.
- A **completion token** controls how the result of an async operation is
  delivered: as a callback, a future, a coroutine awaitable, or a deferred
  operation.
- mdnspp's ASIO adapters use `asio::async_initiate`, so all standard
  completion token forms work out of the box.

## Setup

All examples below share this common setup. Link `mdnspp::asio` in CMake --
this sets `MDNSPP_ENABLE_ASIO_POLICY` automatically.

```cmake
target_link_libraries(my_app PRIVATE mdnspp::asio)
```

The ASIO umbrella header pulls in all adapters and the policy:

```cpp
#include <mdnspp/asio.h>
```

## Callback

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

    mdnspp::basic_observer<mdnspp::AsioPolicy> obs{io, {},
        [](const mdnspp::endpoint &sender, const mdnspp::mdns_record_variant &rec)
        {
            std::visit([&](const auto &r) {
                std::cout << sender.address << ":" << sender.port
                    << " -> " << r << "\n";
            }, rec);
        }
    };

    mdnspp::async_observe(obs,
        [](std::error_code ec)
        {
            if (ec)
                std::cerr << "observe error: " << ec.message() << "\n";
        });

    io.run();
}
```

Completion signature: `void(std::error_code)`.

## use_future

Pass `asio::use_future` to get a `std::future` back. The future throws
`std::system_error` if the operation completes with an error code.

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

    mdnspp::basic_querier<mdnspp::AsioPolicy> q{io, std::chrono::seconds(3)};

    std::future<std::vector<mdnspp::mdns_record_variant>> fut =
        mdnspp::async_query(q, "_http._tcp.local.", mdnspp::dns_type::ptr,
                            asio::use_future);

    io.run();

    try
    {
        auto results = fut.get();
        std::cout << "query complete -- " << results.size() << " record(s)\n";
        for (const auto &rec : results)
            std::visit([](const auto &r) { std::cout << "  " << r << "\n"; }, rec);
    }
    catch (const std::system_error &e)
    {
        std::cerr << "query error: " << e.what() << "\n";
    }
}
```

Completion signature: `void(std::error_code, std::vector<mdns_record_variant>)`.
With `use_future`, the error code is converted to an exception and the second
argument becomes the future's value type.

## use_awaitable

Pass `asio::use_awaitable` inside a coroutine to `co_await` the result.
Spawn the coroutine with `asio::co_spawn`.

```cpp
#include <mdnspp/asio.h>
#include <mdnspp/basic_service_discovery.h>
#include <mdnspp/records.h>

#include <iostream>
#include <variant>

asio::awaitable<void> discover(asio::io_context &io)
{
    mdnspp::basic_service_discovery<mdnspp::AsioPolicy> sd{
        io, std::chrono::seconds(3)};

    auto results = co_await mdnspp::async_discover(
        sd, "_http._tcp.local.", asio::use_awaitable);

    std::cout << "discovered " << results.size() << " record(s)\n";
    for (const auto &rec : results)
        std::visit([](const auto &r) { std::cout << "  " << r << "\n"; }, rec);
}

int main()
{
    asio::io_context io;
    asio::co_spawn(io, discover(io), asio::detached);
    io.run();
}
```

Completion signature: `void(std::error_code, std::vector<mdns_record_variant>)`.
With `use_awaitable`, errors throw `std::system_error` from the `co_await`
expression. Requires compiler coroutine support (GCC 13+, Clang 18+, MSVC 17+).

## deferred

Pass `asio::deferred` to get a deferred operation that can be invoked later
or composed with other operations.

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

    mdnspp::basic_service_server<mdnspp::AsioPolicy> srv{io, std::move(info)};

    auto op = mdnspp::async_start(srv, asio::deferred);

    std::move(op)(
        [](std::error_code ec)
        {
            if (ec)
                std::cerr << "serve error: " << ec.message() << "\n";
            else
                std::cout << "server stopped\n";
        });

    io.run();
}
```

Completion signature: `void(std::error_code)`. Deferred operations are useful
for composing multiple async steps or delaying initiation.

## Completion signatures

| Adapter | Signature |
|---------|-----------|
| `async_observe` | `void(std::error_code)` |
| `async_query` | `void(std::error_code, std::vector<mdns_record_variant>)` |
| `async_discover` | `void(std::error_code, std::vector<mdns_record_variant>)` |
| `async_browse` | `void(std::error_code, std::vector<resolved_service>)` |
| `async_start` | `void(std::error_code)` |

All adapters accept any completion token satisfying
`asio::completion_token_for` with the corresponding signature. They use
`asio::async_initiate` internally.

## Next steps

- [Policies](policies.md) -- understand the policy architecture
- [API Reference](api/) -- full type documentation
