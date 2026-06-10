# Policies

## Why policies?

mdnspp is policy-parameterized. Every public class template takes a policy
parameter:

```cpp
mdnspp::basic_observer<P>
mdnspp::basic_querier<P>
mdnspp::basic_service_discovery<P>
mdnspp::basic_service_server<P>
```

where `P` satisfies the `Policy` concept.

This design exists for two reasons:

1. **Testability.** `MockPolicy` replaces real sockets and timers with
   in-process fakes, so unit tests run without network access.
2. **Framework independence.** Swapping the policy swaps the entire I/O
   backend &mdash; native sockets, ASIO, or any custom executor &mdash; without
   changing application code.

## The Policy concept

A policy must provide three associated types: an executor, a socket, and a
timer. Both socket and timer must be constructible from the executor (matching
ASIO convention).

```cpp
template <typename P>
concept Policy = requires
    {
        typename P::executor_type;
        typename P::socket_type;
        typename P::timer_type;
    }
    && SocketLike<typename P::socket_type>
    && TimerLike<typename P::timer_type>
    && std::constructible_from<typename P::socket_type, typename P::executor_type>
    && std::constructible_from<typename P::timer_type, typename P::executor_type>
    && std::constructible_from<typename P::socket_type, typename P::executor_type, std::error_code&>
    && std::constructible_from<typename P::timer_type, typename P::executor_type, std::error_code&>
    && std::constructible_from<typename P::socket_type, typename P::executor_type, const socket_options&>
    && std::constructible_from<typename P::socket_type, typename P::executor_type, const socket_options&, std::error_code&>
    && requires(typename P::executor_type ex, detail::move_only_function<void()> fn)
    {
        P::post(ex, std::move(fn));
    };
```

`SocketLike` requires `async_receive`, `send`, and `close`. The `async_receive`
handler receives a `const recv_metadata &` (see below) and a `std::span<std::byte>`
payload. `TimerLike` requires `expires_after`, `async_wait`, and `cancel`.

## recv_metadata

Every received packet is accompanied by a `recv_metadata` value carrying
per-packet metadata extracted by the socket implementation:

```cpp
struct recv_metadata
{
    endpoint              sender;
    std::optional<uint8_t> ttl;
    uint32_t              recv_ifindex{0};
};
```

| Field | Type | Description |
|-------|------|-------------|
| `sender` | `endpoint` | Source address and port of the packet sender. |
| `ttl` | `std::optional<uint8_t>` | IP TTL (IPv4) or hop limit (IPv6) of the received packet. `std::nullopt` when the platform did not supply the value (e.g. AsioSocket, Windows DefaultSocket). |
| `recv_ifindex` | `uint32_t` | OS interface index on which the packet arrived (`IP_PKTINFO`). Zero when not available. |

The `ttl` field enables RFC 6762 §11 receive-side enforcement: packets with
a TTL below `mdns_options::receive_ttl_minimum` (default 255) are silently
discarded. Packets where TTL extraction failed are handled according to
`mdns_options::unknown_ttl_policy` (`accept` by default for backward
compatibility with platforms that do not support TTL extraction).

See [recv_metadata API reference](api/recv_metadata.md) and
[Receive-Side TTL](rfc/receive-ttl.md) for platform extraction details.

## Policy-parameterized types

The following public types are parameterized on a Policy:

```cpp
mdnspp::basic_observer<P>
mdnspp::basic_querier<P>
mdnspp::basic_service_discovery<P>
mdnspp::basic_service_server<P>
mdnspp::basic_service_monitor<P>
mdnspp::basic_nic_monitor<P>
mdnspp::basic_nic_group<P, Peers...>
```

`basic_nic_monitor<P>` monitors OS-level NIC change events (interface up/down,
address changes) and invokes callbacks on the Policy executor.
`basic_nic_group<P, Peers...>` uses an owned `basic_nic_monitor` to
automatically create and destroy per-NIC instances of each peer type
(basic_service_monitor, basic_service_server, basic_observer) as interfaces
appear and disappear. See [NIC Group guide](nic-group.md) and
[nic_group API reference](api/nic_group.md).

## DefaultPolicy

**When to use:** standalone applications, no external dependencies, quick
prototyping.

- Include: `#include <mdnspp/defaults.h>`
- CMake target: `mdnspp::mdnspp`
- Type aliases: `mdnspp::observer`, `mdnspp::querier`,
  `mdnspp::service_discovery`, `mdnspp::service_server`
- Executor: `mdnspp::context` (wraps native sockets and a poll loop)

> **Important:** `ctx.run()` blocks until `ctx.stop()` is called. Without a
> `ctx.stop()` call, your program hangs indefinitely. Every completion
> callback must call `ctx.stop()` when work is done. This is the single most
> important thing to know about DefaultPolicy.

```cpp
#include <mdnspp/defaults.h>
#include <mdnspp/records.h>

#include <iostream>
#include <variant>

int main()
{
    mdnspp::context ctx;

    mdnspp::observer obs{ctx,
        mdnspp::observer_options{
            .on_record = [&](const mdnspp::endpoint &sender,
                             const mdnspp::mdns_record_variant &rec)
            {
                std::visit([&](const auto &r) {
                    std::cout << sender << " -> " << r << "\n";
                }, rec);
                obs.stop(); // stop after first record
            }
        }
    };

    obs.async_observe([&ctx](std::error_code) {
        ctx.stop(); // ctx.stop() ends ctx.run()
    });

    ctx.run();
}
```

Multiple mdnspp components can share the same `mdnspp::context`. Each
component creates its own socket, and the context multiplexes all of them:

```cpp
mdnspp::context ctx;

mdnspp::service_server http_srv{ctx, http_info};
mdnspp::service_server ssh_srv{ctx, ssh_info};
mdnspp::observer       obs{ctx, mdnspp::observer_options{.on_record = on_record}};

http_srv.async_start();
ssh_srv.async_start();
obs.async_observe([&ctx](std::error_code) { ctx.stop(); });
ctx.run(); // drives all three
```

## AsioPolicy

**When to use:** ASIO-based applications that need completion tokens
(futures, coroutines, deferred operations).

- Include: `#include <mdnspp/asio.h>`
- CMake target: `mdnspp::asio`
- Executor: `asio::io_context&`

AsioPolicy types are written with the `basic_*` templates directly:

```cpp
mdnspp::basic_observer<mdnspp::AsioPolicy>
mdnspp::basic_querier<mdnspp::AsioPolicy>
```

ASIO free-function adapters accept any standard completion token:

| Adapter | Completion signature |
|---------|---------------------|
| `async_observe` | `void(std::error_code)` |
| `async_query` | `void(std::error_code, std::vector<mdns_record_variant>)` |
| `async_discover` | `void(std::error_code, std::vector<mdns_record_variant>)` |
| `async_browse` | `void(std::error_code, std::vector<resolved_service>)` |
| `async_start` | `void(std::error_code)` |

```cpp
#include <mdnspp/asio.h>
#include <mdnspp/basic_querier.h>
#include <mdnspp/records.h>

#include <iostream>

int main()
{
    asio::io_context io;

    mdnspp::basic_querier<mdnspp::AsioPolicy> q{io};

    mdnspp::async_query(q, "_http._tcp.local.", mdnspp::dns_type::ptr,
        [](std::error_code ec, std::vector<mdnspp::mdns_record_variant> results)
        {
            if (ec)
                std::cerr << "query error: " << ec.message() << "\n";
            else
                std::cout << "query complete -- " << results.size() << " record(s)\n";
        });

    io.run();
}
```

See [Async Patterns](async-patterns.md) for all completion token forms.

## MockPolicy

**When to use:** unit testing without network access.

- Include: `#include <mdnspp/testing/mock_policy.h>`
- Namespace: `mdnspp::testing`
- Executor: `mdnspp::testing::mock_executor`

MockPolicy provides `MockSocket` (with packet enqueue/send inspection) and
`MockTimer` (with manual fire/cancel control).

```cpp
#include <mdnspp/testing/mock_policy.h>
#include <mdnspp/basic_observer.h>

mdnspp::testing::mock_executor ex;
mdnspp::basic_observer<mdnspp::testing::MockPolicy> obs{ex};
```

## InProcPolicy

**When to use:** in-process multicast simulation, deterministic multi-party
testing, process-local service registry, CI environments without multicast
networking.

- Include: `#include <mdnspp/inproc/inproc_policy.h>`
- CMake target: `mdnspp::inproc`
- Type aliases: `mdnspp::InProcPolicy` (steady_clock), `mdnspp::InProcTestPolicy`
  (test_clock — Catch2 tests only)
- Executor: `mdnspp::inproc::inproc_executor<>`

`InProcPolicy` uses an explicit `inproc_bus` as the shared multicast medium.
No real sockets or OS networking is involved. The executor is created from the
bus and passed to each component.

```cpp
#include <mdnspp/inproc/inproc_policy.h>
#include <mdnspp/basic_service_server.h>
#include <mdnspp/basic_service_monitor.h>

mdnspp::inproc::inproc_bus<>      bus;
mdnspp::inproc::inproc_executor<> executor{bus};

mdnspp::basic_service_server<mdnspp::InProcPolicy>  srv{executor, info};
mdnspp::basic_service_monitor<mdnspp::InProcPolicy> mon{executor, opts};

srv.async_start();
mon.watch("_http._tcp.local.");
mon.async_start([&executor](std::error_code) { executor.stop(); });

executor.run();   // blocks until executor.stop() — same as ctx.run()
```

All components must share the same `executor` (and by extension the same `bus`).

See [In-Process Bus guide](inproc-bus.md) for architecture, bus topology, and full
usage patterns.

## Thread-safe work scheduling: post()

Every Policy provides a static `post(executor_type, move_only_function<void()>)`
for thread-safe work scheduling. This is how mdnspp dispatches work onto the
correct event loop from any thread.

### DefaultPolicy

```cpp
static void post(executor_type ex, detail::move_only_function<void()> fn)
{
    ex.post(std::move(fn));
}
```

Queues the function onto the `DefaultContext` poll loop. The work executes on
the thread calling `ctx.run()`.

### AsioPolicy

```cpp
static void post(executor_type ex, detail::move_only_function<void()> fn)
{
    asio::post(ex, std::move(fn));
}
```

Uses ASIO's strand-safe posting mechanism.

### MockPolicy

```cpp
static void post(executor_type ex, detail::move_only_function<void()> fn)
{
    ex.m_posted.push_back(std::move(fn));
}
```

Appends to a deque for deterministic testing. Drain posted work with
`ex.drain_posted()`.

### InProcPolicy

```cpp
static void post(executor_type ex, detail::move_only_function<void()> fn)
{
    ex.post(std::move(fn));
}
```

Enqueues the function onto the `inproc_executor` posted-work deque. Work is
processed in the next `drain()` or `run()` cycle on the thread driving the
executor.

### Usage

`post()` is used internally by `update_service_info()` to safely modify a
running service server from any thread. Application code can also use it
directly for custom thread-safe operations on the executor.

## Server Lifecycle

When using `basic_service_server`, the server progresses through a defined
state machine after `async_start()` is called:

- **idle** &mdash; constructed but not yet started.
- **probing** &mdash; sends 3 probe queries at 250 ms intervals (with a random
  0--250 ms initial delay) to verify name uniqueness (RFC 6762 section 8.1).
  Any conflicting response triggers the `service_options::on_conflict`
  callback.
- **announcing** &mdash; sends a configurable burst of unsolicited announcements
  (`announce_count` packets at `announce_interval` intervals, default 2
  packets at 1 second) per RFC 6762 section 8.3.
- **live** -- the server responds to matching queries with RFC 6762-delayed
  responses (20--120 ms random delay for multicast). The `on_ready` handler
  fires at this point.
- **stopped** -- `stop()` was called or conflict resolution failed. Goodbye
  packets are sent if `service_options::send_goodbye` is `true`.

See [`service_options`](api/service_options.md) for controlling probing,
announcing, goodbye, and conflict resolution behavior.

## Choosing a policy

| Need | Use | CMake target |
|------|-----|--------------|
| Standalone, no dependencies | DefaultPolicy | `mdnspp::mdnspp` |
| ASIO integration | AsioPolicy | `mdnspp::asio` |
| Unit testing | MockPolicy | `mdnspp::testing` |
| In-process simulation / testing | InProcPolicy | `mdnspp::inproc` |
| PSK-encrypted mDNS multicast | `encrypted_policy<Inner>` | `mdnspp::mdnspp_encrypt` |

See [Encrypted mDNS](encrypt/README.md) for setup and the [encrypted_policy API reference](encrypt/api/encrypted_policy.md).

## Next steps

- [Async Patterns](async-patterns.md) -- ASIO completion token forms
- [CMake Integration](cmake-integration.md) -- linking targets and build options
- [API Reference](api/) -- full type signatures
