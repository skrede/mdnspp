# Local Bus

`LocalPolicy` provides an in-process multicast simulation layer for mdnspp.
No real sockets are opened, no network packets leave the process. All delivery
happens through a shared `local_bus` object that mediates between components
within the same process.

This guide covers production use of `LocalPolicy` (steady_clock, real-time
execution with `run()`). For test-clock usage inside Catch2 tests, see
`local_harness` in `lib/mdnspp-local/include/mdnspp/local/local_harness.h`.

## Architecture

Four types form the local bus stack:

| Type | Role |
|------|------|
| `local_bus<Clock>` | Shared multicast medium. Holds all registered sockets and a packet queue. |
| `local_socket<Clock>` | Per-component I/O. Sends by enqueuing onto the bus; receives via `deliver()` called by the bus. |
| `local_timer<Clock>` | Scheduling. Fires based on `Clock::now()` when `try_fire()` is called by the executor. |
| `local_executor<Clock>` | Event loop driver. Runs posted callbacks, fires expired timers, and delivers packets. |

All four are template classes parameterised on a `Clock`. `LocalPolicy` aliases
`local_policy<std::chrono::steady_clock>`, which wires these together under the
standard `Policy` concept.

## Bus topology

`local_bus` maintains a list of registered sockets and an outbound packet
queue. Each `local_socket` is registered on construction and deregistered on
destruction.

**Port assignment.** The bus assigns each socket a unique `127.0.0.1:NNNN`
endpoint, starting at port 10000. These ports are not real OS ports — they are
internal identifiers used to distinguish sockets on the bus.

**Packet delivery.** `local_socket::send()` enqueues onto the bus queue rather
than delivering inline. This avoids re-entrancy in multi-party scenarios.
`local_executor::step()` calls `deliver_one()` which dequeues one packet and
dispatches it:

- **Unicast:** a packet addressed to a specific endpoint goes to the socket
  whose assigned endpoint matches exactly.
- **Multicast:** a packet addressed to a multicast group endpoint goes to every
  socket in the matching multicast group. The sender's own socket is skipped if
  `loopback_mode::disabled` is set in `socket_options` (the default for mDNS
  multicast sockets).

**Multicast group isolation.** Sockets join a group by setting
`socket_options::multicast_group`. Only sockets in the same group receive
multicast packets for that group. Sockets not joined to the group are invisible
to multicast traffic for it.

## Executor model

`local_executor` drives all activity with a three-priority loop:

1. Posted callbacks (`post()` queue) — processed first.
2. Expired timers — checked against `Clock::now()`.
3. Packet delivery — one packet dequeued per `step()` call.

`step()` returns `true` if any work was done. `drain()` calls `step()` until
the system reaches quiescence (no posted work, no expired timers, no pending
packets).

`run()` loops `drain()` + `sleep_for(1ms)` until `stop()` is called. This
models the same blocking-loop pattern as `DefaultContext::run()`.

## Usage pattern

```cpp
#include <mdnspp/local/local_policy.h>
#include <mdnspp/basic_service_server.h>
#include <mdnspp/basic_service_monitor.h>
#include <mdnspp/service_info.h>
#include <mdnspp/service_options.h>
#include <mdnspp/monitor_options.h>

mdnspp::local::local_bus<>      bus;
mdnspp::local::local_executor<> executor{bus};

mdnspp::service_info info{
    .service_name = "MyApp._http._tcp.local.",
    .service_type = "_http._tcp.local.",
    .hostname     = "myhost.local.",
    .port         = 8080,
    .address_ipv4 = "127.0.0.1",
};

mdnspp::basic_service_server<mdnspp::LocalPolicy>  srv{executor, info};
mdnspp::basic_service_monitor<mdnspp::LocalPolicy> mon{
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
target_link_libraries(your_target PRIVATE mdnspp::local)
```

`mdnspp::local` is defined in `lib/mdnspp-local/CMakeLists.txt` and exports the
`mdnspp/local/` include directory. You do not need to link `mdnspp::mdnspp`
separately — `mdnspp::local` brings it in as a dependency.

## When to use LocalPolicy

| Use case | Notes |
|----------|-------|
| In-process service simulation | Multiple components interacting without real network or OS sockets. |
| Testing without network | Deterministic, hermetic — no firewall rules, no multicast routing, no port conflicts. |
| Process-local service registry | Multiple threads or coroutines in one process discovering each other by service type. |
| CI environments without multicast | DefaultPolicy requires multicast-capable networking. LocalPolicy does not. |

**What LocalPolicy is not.** It does not replace DefaultPolicy for real network
mDNS. There are no actual UDP sockets, no IP_ADD_MEMBERSHIP calls, and no
packets leave the process. Use DefaultPolicy or AsioPolicy when you need real
multicast on the local network.

## See also

- [policies.md](policies.md) — overview of all built-in policies and the Policy concept
- [custom-policies.md](custom-policies.md) — LocalPolicy as a worked example of the Policy concept
- [testing.md](testing.md) — how LocalPolicy is used in the integration test suite
