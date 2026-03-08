# service_server

Announces an mDNS service on the local network and responds to matching queries with DNS records. Implements the full RFC 6762 service lifecycle: probing for name uniqueness, announcing, responding with random 20--120 ms delay (RFC 6762 section 6) for multicast responses, sending goodbye packets on shutdown, known-answer suppression, and unicast responses when the QU bit is set.

## Header and Alias

| Form | Header |
|------|--------|
| `basic_service_server<P>` | `#include <mdnspp/basic_service_server.h>` |
| `mdnspp::service_server` (DefaultPolicy alias) | `#include <mdnspp/defaults.h>` |

```cpp
// Template form
template <Policy P>
class basic_service_server;

// DefaultPolicy alias (from defaults.h)
using service_server = basic_service_server<DefaultPolicy>;
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
using query_callback     = std::move_only_function<void(const endpoint&, dns_type, response_mode)>;
using completion_handler = std::move_only_function<void(std::error_code)>;
using error_handler     = detail::move_only_function<void(std::error_code, std::string_view)>;
```

`query_callback` is retained as a type alias for the query notification signature. Set it via [`service_options::on_query`](service_options.md) rather than as a constructor parameter.

## Constructors

### Throwing

```cpp
explicit basic_service_server(executor_type ex, service_info info,
                              service_options opts = {},
                              socket_options sock_opts = {});
```

Constructs the server from an executor and a [`service_info`](#service_info) describing the service to announce. The optional [`service_options`](service_options.md) controls probing, announcing, goodbye, and query notification behavior. The optional `sock_opts` controls network interface selection, multicast TTL, and loopback (see [Socket Options](../socket-options.md)). Throws on socket construction failure.

### Non-throwing

```cpp
basic_service_server(executor_type ex, service_info info,
                     service_options opts, socket_options sock_opts,
                     std::error_code& ec);
```

Same as the throwing constructor, but sets `ec` instead of throwing on failure. All parameters must be provided explicitly (no defaults).

## Methods

### async_start

```cpp
void async_start(completion_handler on_ready = {}, completion_handler on_done = {});
```

Begins the probe -> announce -> live sequence and returns immediately.

- **Probing:** sends 3 probe queries at 250 ms intervals (with a random 0--250 ms initial delay per RFC 6762 section 8.1). If a conflicting response is detected, `service_options::on_conflict` is called.
- **Announcing:** sends `announce_count` unsolicited announcements at `announce_interval` intervals.
- **Live:** the server responds to matching queries.

The `on_ready` handler fires with `std::error_code{}` when the server reaches the live state, or with `mdns_error::probe_conflict` if conflict resolution fails. The `on_done` handler fires with `std::error_code{}` when `stop()` is called.

Must only be called once per lifetime.

### stop

```cpp
void stop();
```

Idempotent. Sends a goodbye packet (TTL=0) if `service_options::send_goodbye` is `true` and the server is in the live or announcing state. Fires `on_ready` with `operation_canceled` if still probing or announcing, then fires `on_done`. Cancels the response timer and destroys the receive loop. The destructor calls `stop()` automatically for RAII safety.

### on_error

```cpp
void on_error(error_handler handler);
```

Sets a handler invoked when a fire-and-forget send operation fails (e.g. during probing, announcing, or response sending). The handler receives the error code and a context string identifying the send site (e.g. `"probe send"`, `"goodbye send"`). Without a handler, send errors are silently ignored.

### update_service_info

```cpp
void update_service_info(service_info new_info);
```

Replaces the service's metadata at runtime and multicasts an unsolicited announcement burst with all records (PTR, SRV, TXT, A/AAAA) per RFC 6762 section 8.4. The number of announcements and their interval are controlled by `service_options::announce_count` and `service_options::announce_interval`.

**Thread-safety:** May be called from any thread. Internally uses `P::post()` to schedule the update on the server's event loop, ensuring no data races with the receive loop.

**Liveness guard:** The posted work captures a `std::weak_ptr` to the server's internal liveness sentinel. If the server is destroyed or stopped before the posted work executes, the update is silently discarded -- no dangling pointer access.

**Precondition:** Must only be called on a running server (after `async_start()`, before `stop()`).

**Example:**

```cpp
mdnspp::service_server srv{ctx, std::move(info)};
srv.async_start();

// From another thread:
srv.update_service_info(mdnspp::service_info{
    .service_name = "MyApp._http._tcp.local.",
    .service_type = "_http._tcp.local.",
    .hostname     = "myhost.local.",
    .port         = 9090,  // port changed
    .address_ipv4 = "192.168.1.69",
});
// Announcement is multicast automatically after the update executes on the event loop.
```

### Accessors

```cpp
const socket_type& socket()     const noexcept;
      socket_type& socket()           noexcept;
const timer_type&  timer()      const noexcept;  // response delay timer
      timer_type&  timer()            noexcept;
const timer_type&  recv_timer() const noexcept;  // receive loop timer
      timer_type&  recv_timer()       noexcept;
```

The server uses two timers: `timer()` for the RFC 6762 random response delay (20--120 ms for multicast), and `recv_timer()` for the internal receive loop.

## Lifecycle

The server progresses through five states:

| State | Description |
|-------|-------------|
| **idle** | Constructed but `async_start()` not yet called. |
| **probing** | Sending probe queries to check name uniqueness (3 probes at 250 ms intervals). Incoming responses are checked for conflicts. |
| **announcing** | Sending unsolicited announcement burst (`announce_count` packets at `announce_interval`). |
| **live** | Responding to matching queries with RFC 6762-delayed responses. `on_ready` has fired. |
| **stopped** | `stop()` called or conflict resolution failed. `on_done` has fired. |

```
idle -> probing -> announcing -> live -> stopped
                \                        ^
                 -> (conflict) ----------/
```

Conflict during probing invokes `service_options::on_conflict`. If the callback returns `true`, probing restarts with the new name. If it returns `false` (or no callback is set), the server transitions directly to stopped and fires `on_ready` with `mdns_error::probe_conflict`.

## Supporting Types

### service_info

```cpp
struct service_info {
    std::string                service_name;   // e.g. "MyApp._http._tcp.local."
    std::string                service_type;   // e.g. "_http._tcp.local."
    std::string                hostname;       // e.g. "myhost.local."
    uint16_t                   port{0};
    uint16_t                   priority{0};    // SRV priority (lower = preferred)
    uint16_t                   weight{0};      // SRV weight (load balancing)
    std::optional<std::string> address_ipv4;   // e.g. "192.168.1.10"
    std::optional<std::string> address_ipv6;   // e.g. "fe80::1"
    std::vector<service_txt>   txt_records;    // RFC 6763 key/value entries
    std::vector<std::string>   subtypes;       // e.g. {"_printer"} for subtype enumeration
};
```

Defined in `<mdnspp/service_info.h>`. Describes the service to announce. The `subtypes` field lists DNS-SD subtype labels (RFC 6763 section 7.1) for subtype-filtered discovery and optional subtype announcement (see `service_options::announce_subtypes`).

Use C++20 designated initializers for readability:

```cpp
mdnspp::service_info info{
    .service_name = "MyApp._http._tcp.local.",
    .service_type = "_http._tcp.local.",
    .hostname     = "myhost.local.",
    .port         = 8080,
    .address_ipv4 = "192.168.1.10",
    .txt_records  = {{"path", "/index.html"}},
    .subtypes     = {"_printer"},
};
```

### query_callback

```cpp
using query_callback = std::move_only_function<void(const endpoint&, dns_type, response_mode)>;
```

Called when a matching mDNS query is received. Set via [`service_options::on_query`](service_options.md).

| Parameter | Type | Description |
|-----------|------|-------------|
| `sender` | `endpoint` | The querier's address and port |
| `qtype` | `dns_type` | The record type requested (PTR, SRV, A, etc.) |
| `mode` | `response_mode` | `unicast` if the QU bit was set (RFC 6762 section 5.4), `multicast` otherwise |

### service_txt

```cpp
struct service_txt {
    std::string                key;
    std::optional<std::string> value;
};
```

Defined in `<mdnspp/records.h>`. Represents a single RFC 6763 TXT key/value pair. Key-only entries have `value == std::nullopt`.

## Usage Example

```cpp
// Announce an HTTP service on port 8080, print incoming queries.

#include <mdnspp/defaults.h>
#include <mdnspp/service_info.h>

#include <iostream>
#include <thread>

int main()
{
    mdnspp::context ctx;

    mdnspp::service_info info{
        .service_name = "MyApp._http._tcp.local.",
        .service_type = "_http._tcp.local.",
        .hostname     = "myhost.local.",
        .port         = 8080,
        .address_ipv4 = "192.168.1.69",
        .txt_records  = {{"path", "/index.html"}},
    };

    mdnspp::service_options opts;
    opts.on_query = [](const mdnspp::endpoint &sender, mdnspp::dns_type qtype, mdnspp::response_mode mode)
    {
        std::cout << sender << " queried qtype=" << to_string(qtype)
                  << " (" << to_string(mode) << ")\n";
    };

    mdnspp::service_server srv{ctx, std::move(info), std::move(opts)};

    std::thread shutdown{[&ctx] {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        ctx.stop();
    }};

    std::cout << "Serving MyApp._http._tcp.local. on port 8080 (30s then auto-stop)\n";
    srv.async_start();
    ctx.run();

    shutdown.join();
}
```

## Multiple Servers on One Context

Multiple `service_server` instances can share the same executor. Each server
creates its own socket, and the context multiplexes all of them. This works
with both DefaultPolicy and AsioPolicy.

```cpp
mdnspp::context ctx;

mdnspp::service_server http_srv{ctx, http_info};
mdnspp::service_server ssh_srv{ctx, ssh_info};

http_srv.async_start();
ssh_srv.async_start();
ctx.run(); // drives both servers
```

The same applies to mixing types -- an `observer` and a `service_server` can
share a context, as can any combination of mdnspp components.

## See Also

- [service_options](service_options.md) -- controls probing, announcing, goodbye, conflict resolution
- [service_discovery](service_discovery.md) -- discover services announced by servers
- [resolved_service](resolved_service.md) -- the aggregated service type
- [observer](observer.md) -- passively listen to all mDNS traffic
- [Socket Options](../socket-options.md) -- network interface selection, multicast TTL, loopback control
