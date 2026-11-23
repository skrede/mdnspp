# In-Process Bus

`inproc_policy` provides an in-process multicast simulation layer for mdnspp.
No real sockets are opened, no network packets leave the process. All delivery
happens through a shared `inproc_bus` object that mediates between components
within the same process.

This guide covers production use of `inproc_policy` (steady_clock, real-time
execution with `run()`). For test-clock usage inside Catch2 tests, see
`inproc_harness` in [Test Landscape](testing.md#protocol-integration-tests-inproc).

## Architecture

Four types form the in-process bus stack:

| Type | Role |
|------|------|
| `inproc_bus<Clock>` | Shared multicast medium. Holds all registered sockets and a packet queue. |
| `inproc_socket<Clock>` | Per-component I/O. Sends by enqueuing onto the bus; receives via `deliver()` called by the bus. |
| `inproc_timer<Clock>` | Scheduling. Fires based on `Clock::now()` when `try_fire()` is called by the executor; `expires_after()` and `cancel()` complete a pending wait inline with `operation_canceled`. |
| `inproc_executor<Clock>` | Event loop driver. Runs posted callbacks, fires expired timers, and delivers packets. |

All four are template classes parameterized on a `Clock`. `inproc_policy` aliases
`inproc_policy<std::chrono::steady_clock>`, which wires these together under the
standard `policy_like` concept.

## Bus topology

`inproc_bus` maintains a list of registered sockets and an outbound packet
queue. Each `inproc_socket` is registered on construction and deregistered on
destruction.

**Endpoint assignment.** The bus assigns each socket a distinct loopback
address: the first socket gets `127.0.0.1`, the next `127.0.0.2`, and so on
through `127.0.0.255`, `127.0.1.0` and onward across `127.0.0.0/8`. The port
is the one given to the `inproc_bus` constructor (default 5353), or the
socket's `inproc_socket_options::port_override` when set. Addresses are never
reused over a bus's lifetime, so no two sockets, live or closed, share an
endpoint. Once all 16,777,214 addresses (the /8 without its network and
broadcast addresses) have been handed out, registration fails: the
`std::error_code` constructors of `inproc_socket` set
`std::errc::address_not_available` and leave the socket closed, and the
throwing constructors throw `std::system_error` with that code. These
endpoints are not real OS addresses — they are internal identifiers used to
distinguish sockets on the bus.

**Packet delivery.** `inproc_socket::send()` enqueues onto the bus queue rather
than delivering inline. This avoids re-entrancy in multi-party scenarios.
After `close()`, the error_code overload of `send()` reports
`std::errc::bad_file_descriptor` and the throwing overload throws
`std::system_error` with that code, matching the native socket.
`inproc_executor::step()` calls `deliver_one()` which dequeues one packet and
dispatches it:

- **Unicast:** a packet addressed to a specific endpoint goes to the socket
  whose assigned endpoint matches exactly.
- **Multicast:** a packet addressed to a multicast group endpoint goes to every
  socket in the matching multicast group, including the sender's own socket —
  `socket_options::multicast_loopback` defaults to `loopback_mode::enabled`.
  Set `loopback_mode::disabled` to skip delivery back to the sender.

**Receive metadata.** Every delivery reports the sender's assigned endpoint as
`recv_metadata::sender`, a TTL of 255 and interface index 0. Its `destination`
is the group address for a multicast delivery (`224.0.0.251` or `ff02::fb` for
the default groups) and the receiving socket's assigned `127.x.y.z` address for
a unicast delivery. Tests that need other metadata (an unknown TTL, a unicast
destination, an off-link sender) hand a `recv_metadata` and the packet bytes
straight to the socket with `inproc_socket::deliver(const recv_metadata &,
std::span<const std::byte>)`, which bypasses the bus.

**Handlers that open or close sockets.** Delivery runs the receiving socket's
pending receive handler synchronously, and that handler may open, close or
destroy sockets on the same bus. A multicast packet goes to the sockets that
were registered when its delivery began, each at most once; a socket closed or
destroyed by an earlier handler is skipped, and a socket opened during the
delivery does not receive that packet (it receives the packets dequeued after
it). A unicast packet goes to one socket only, so nothing is read from the
socket list after its handler runs.

**Multicast group isolation.** Sockets join a group by setting
`socket_options::multicast_group`. Only sockets in the same group receive
multicast packets for that group. Sockets not joined to the group are invisible
to multicast traffic for it.

**Port override.** The inproc policy declares its own socket options type,
`mdnspp::inproc::inproc_socket_options` (derived from `socket_options`, used
automatically by `basic_*` constructors via `policy_socket_options_t<P>`). Its
`port_override` field (`std::optional<uint16_t>`) replaces the bus-assigned
port, simulating legacy unicast clients that query from a source port other
than 5353 (RFC 6762 §6.7).

## Executor model

`inproc_executor` drives all activity with a three-priority loop. Each
`step()` does one unit of work, taken from the first of these sources that has
any:

1. Posted callbacks (`post()` queue) — one callback, in posting order.
2. Expired timers — the first registered timer whose expiry has passed against
   `Clock::now()` fires.
3. Packet delivery — one packet dequeued from the bus.

`step()` returns `true` if any work was done. `drain()` calls `step()` until
the system reaches quiescence (no posted work, no expired timers, no pending
packets).

`run()` loops `drain()` + `sleep_for(1ms)` until `stop()` is called. This
models the same blocking-loop pattern as `default_context::run()`.

**Threading.** `post()` and `stop()` may be called from any thread. A callable
posted from another thread enters a mutex-protected ingress that the next
`step()` drains into the posted queue, so callables posted from one thread run
in their posting order. Stepping (`step()`, `drain()`, `run()`), the sockets,
the timers and the bus belong to the one thread that drives the executor; other
threads reach them only through `post()`.

## Usage pattern

```cpp
#include <mdnspp/inproc/inproc_policy.h>
#include <mdnspp/basic_service_server.h>
#include <mdnspp/basic_service_monitor.h>
#include <mdnspp/service_info.h>
#include <mdnspp/service_options.h>
#include <mdnspp/monitor_options.h>

mdnspp::inproc::inproc_bus<>      bus;
mdnspp::inproc::inproc_executor<> executor{bus};

mdnspp::service_info info{
    .service_name = "MyApp._http._tcp.local.",
    .service_type = "_http._tcp.local.",
    .hostname     = "myhost.local.",
    .port         = 8080,
    .address_ipv4 = "127.0.0.1",
};

mdnspp::basic_service_server<mdnspp::inproc_policy>  srv{executor, info};
mdnspp::basic_service_monitor<mdnspp::inproc_policy> mon{
    executor,
    mdnspp::monitor_options{
        .on_found = [](const mdnspp::resolved_service &svc) { /* ... */ },
        .on_lost  = [&executor](const mdnspp::resolved_service &) {
            executor.stop();
        },
    },
};

srv.async_start();
mon.watch("_http._tcp.local.");
mon.async_start([](std::error_code) {});

executor.run();   // blocks; drives all components via steady_clock
```

All `basic_*` components must share the same `executor` (and by extension the
same `bus`). Mixing components from different bus instances produces no packet
delivery between them — they cannot see each other's traffic.

## CMake integration

```cmake
target_link_libraries(your_target PRIVATE mdnspp::inproc)
```

`mdnspp::inproc` is defined in `lib/mdnspp-inproc/CMakeLists.txt` and exports the
`mdnspp/inproc/` include directory. You do not need to link `mdnspp::mdnspp`
separately — `mdnspp::inproc` brings it in as a dependency.

## When to use inproc_policy

| Use case | Notes |
|----------|-------|
| In-process service simulation | Multiple components interacting without real network or OS sockets. |
| Testing without network | Deterministic, hermetic — no firewall rules, no multicast routing, no port conflicts. |
| Process-local service registry | Components in one process discovering each other by service type. All of them run on the thread that drives the shared executor; other threads hand work to it with `post()`. |
| CI environments without multicast | default_policy requires multicast-capable networking. inproc_policy does not. |

**What inproc_policy is not.** It does not replace default_policy for real network
mDNS. There are no actual UDP sockets, no IP_ADD_MEMBERSHIP calls, and no
packets leave the process. Use default_policy or asio_policy when you need real
multicast on the local network.

## See also

- [policies.md](policies.md) — overview of all built-in policies and the policy_like concept
- [custom-policies.md](custom-policies.md) — inproc_policy as a worked example of the policy_like concept
- [testing.md](testing.md) — how inproc_policy is used in the integration test suite
