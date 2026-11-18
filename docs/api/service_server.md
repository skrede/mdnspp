# service_server

Announces an mDNS service on the local network and responds to matching queries with DNS records. Implements the full RFC 6762 service lifecycle: probing for name uniqueness, announcing, per-question answering with NSEC negative responses, sending goodbye packets on shutdown, known-answer suppression, and unicast responses when the QU bit is set. Multicast responses containing shared records (PTR) are delayed by a random 20--120 ms interval (RFC 6762 section 6); responses carrying only unique, probe-verified records are sent immediately.

## Header and Alias

| Form | Header |
|------|--------|
| `basic_service_server<P>` | `#include <mdnspp/basic_service_server.h>` |
| `mdnspp::service_server` (default_policy alias) | `#include <mdnspp/defaults.h>` |

```cpp
// Template form
template <policy_like P>
class basic_service_server;

// default_policy alias (from defaults.h)
using service_server = basic_service_server<default_policy>;
```

## Template Parameters

| Parameter | Constraint | Description |
|-----------|------------|-------------|
| `P` | satisfies `policy_like` | Provides `executor_type`, `socket_type`, and `timer_type`. See [policies](../policies.md). |

## Type Aliases

```cpp
using executor_type  = typename P::executor_type;
using socket_type    = typename P::socket_type;
using timer_type     = typename P::timer_type;
using query_callback = move_only_function<void(const endpoint&, dns_type, response_mode)>;
```

Callback types are defined in `<mdnspp/callback_types.h>` (included transitively):

```cpp
using completion_handler = mdnspp::server_completion_handler; // void(std::error_code)
using error_handler      = mdnspp::error_handler;             // void(std::error_code, std::string_view)
```

`query_callback` is retained as a type alias for the query notification signature. Set it via [`service_options::on_query`](service_options.md) rather than as a constructor parameter.

## Constructors

### Throwing

```cpp
explicit basic_service_server(executor_type ex, service_info info,
                              service_options opts = {},
                              policy_socket_options_t<P> sock_opts = {},
                              mdns_options mdns_opts = {});
```

Constructs the server from an executor and a [`service_info`](#service_info) describing the service to announce. The optional [`service_options`](service_options.md) controls probing, announcing, goodbye, query notification, and error reporting behavior. The optional `sock_opts` controls network interface selection, multicast TTL, and loopback (see [Socket Options](../socket-options.md)); its type is `policy_socket_options_t<P>` — plain `socket_options` for the default and asio policies, the policy's derived options type otherwise (e.g. `encrypt_socket_options`). The optional [`mdns_options`](mdns_options.md) controls TC accumulation windows and known-answer suppression limits.

Options are validated at construction: empty or invalid service names, zero `probe_count` or `announce_count`, non-positive intervals or TTLs, and inconsistent delay/fraction ranges fail with `std::errc::invalid_argument`, thrown as `std::system_error`. Socket construction failure also throws.

### Non-throwing

```cpp
basic_service_server(executor_type ex, service_info info,
                     service_options opts, policy_socket_options_t<P> sock_opts,
                     mdns_options mdns_opts, std::error_code &ec);
```

Same as the throwing constructor, but sets `ec` instead of throwing — both for socket construction failure and for invalid options (`std::errc::invalid_argument`). All parameters must be provided explicitly (no defaults).

`basic_service_server` is non-copyable and non-movable: completion handlers capture `this`.

**TC handling and duplicate answer suppression** are automatic when the server is constructed with `mdns_options`. When a query arrives with the TC (truncation) bit set, the server accumulates continuation packets for a random interval in `[tc_wait_min, tc_wait_max]` before processing the full known-answer set. See [tc-handling](../rfc/tc-handling.md) and [duplicate-suppression](../rfc/duplicate-suppression.md) for details.

## Methods

### async_start

```cpp
void async_start(completion_handler on_ready = {}, completion_handler on_done = {});
```

Begins the probe -> announce -> live sequence and returns immediately.

- **Probing:** sends 3 probe queries at 250 ms intervals (with a random 0--250 ms initial delay per RFC 6762 section 8.1), probing both the service instance name and the hostname. If a conflicting response is detected, `service_options::on_conflict` is called.
- **Announcing:** sends `announce_count` unsolicited announcements at `announce_interval` intervals.
- **Live:** the server responds to matching queries and continues conflict monitoring (RFC 6762 section 9).

Completion semantics:

- `on_ready` fires once with the startup outcome: `std::error_code{}` when the server reaches the live state; `mdns_error::probe_conflict` when conflict resolution fails permanently (the `on_conflict` callback returned `std::nullopt` or was not set); `std::errc::invalid_argument` when the service names cannot be encoded; `std::errc::operation_canceled` when `stop()` is called before the server is live.
- `on_done` ALWAYS fires with `std::error_code{}` after teardown completes — both on `stop()` and on the permanent-probe-failure path. A program waiting for `on_done` therefore never hangs after a conflict dead-end.

`async_start` is one-shot: a second call completes `on_ready` with `std::errc::operation_in_progress`; a call after `stop()` completes `on_ready` with `std::errc::invalid_argument`. The misuse completion is posted to the executor, never invoked inline on the caller thread. The running sequence is unaffected.

### stop

```cpp
void stop();
```

Idempotent and callable from any thread. Posts the teardown to the executor, so all state mutations -- including building the goodbye packet (when `service_options::send_goodbye` is `true`) from the current service information and sending it -- happen on the executor thread. The goodbye is sent only when the server was announcing or live (RFC 6762 section 10.1); consequently a goodbye goes out only if the executor runs after `stop()`. If the server is still probing or announcing, `on_ready` fires with `std::errc::operation_canceled`; `on_done` then fires with `std::error_code{}` after teardown. The destructor calls `stop()` automatically for RAII safety and completes still-pending handlers with `std::errc::operation_canceled` rather than dropping them.

### update_service_info

```cpp
void update_service_info(service_info new_info);
```

Replaces the service's metadata at runtime. When `service_name` and `hostname` are unchanged, an unsolicited announcement burst with all records (PTR, SRV, TXT, A/AAAA) is multicast per RFC 6762 section 8.4; the number of announcements and their interval are controlled by `service_options::announce_count` and `service_options::announce_interval`. A changed `service_name` or `hostname` is a new record set and re-enters probing first (RFC 6762 section 8.1). When the replacement info carries `auto_address` (a `service_info::make()` result), its unset address fields are re-resolved under the `async_start` rule before the announcement (see [service_info](service_info.md)).

**Thread-safety:** May be called from any thread. Internally uses `P::post()` to schedule the update on the server's event loop, ensuring no data races with the receive loop.

**Liveness guard:** The posted work captures a `std::weak_ptr` to the server's internal liveness sentinel. If the server is destroyed or stopped before the posted work executes, the update is silently discarded &mdash; no dangling pointer access.

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

### Error reporting

Fire-and-forget send failures (probe, announce, response, goodbye sends) and address encoding errors are reported through the `service_options::on_error` field:

```cpp
mdnspp::service_options opts{
    .on_error = [](std::error_code ec, std::string_view context)
    {
        std::cerr << context << ": " << ec.message() << std::endl;
    },
};
```

The handler receives the error code and a context string identifying the failure site (e.g. `"probe send"`, `"goodbye send"`). Without a handler, send errors are silently ignored.

### Accessors

```cpp
const socket_type& socket()     const noexcept;
      socket_type& socket()           noexcept;
const timer_type&  timer()      const noexcept;  // response delay timer
      timer_type&  timer()            noexcept;
const timer_type&  tc_timer()   const noexcept;  // TC accumulation timer
      timer_type&  tc_timer()         noexcept;
const timer_type&  recv_timer() const noexcept;  // receive loop timer
      timer_type&  recv_timer()       noexcept;
```

The server uses three timers: `timer()` for the RFC 6762 random response delay (20--120 ms for multicast) and the probe/announce schedule, `tc_timer()` for truncated-query known-answer accumulation, and `recv_timer()` for the internal receive loop.

## Lifecycle

The server progresses through five states:

| State | Description | Handler activity |
|-------|-------------|------------------|
| **idle** | Constructed but `async_start()` not yet called. | — |
| **probing** | Sending probe queries (3 probes at 250 ms intervals) for the instance name and hostname. Incoming responses and simultaneous probes are checked for conflicts (§8.1, §8.2.1). | `stop()` here fires `on_ready` with `operation_canceled`. |
| **announcing** | Sending the unsolicited announcement burst (`announce_count` packets at `announce_interval`). | `stop()` here fires `on_ready` with `operation_canceled`; a goodbye is sent. |
| **live** | Responding to matching queries; post-probe conflict monitoring active (§9). | `on_ready` has fired with `std::error_code{}`. |
| **stopped** | `stop()` called or conflict resolution failed permanently. | `on_done` has fired with `std::error_code{}` after teardown. |

```
idle -> probing -> announcing -> live -> stopped
           |   \                  |        ^
           |    -> (rename) ------+--------|   <- on_conflict returned a new name: re-probe
           |                      |        |
            -> (give up) ---------+--------    <- on_conflict returned std::nullopt:
                                                  on_ready(probe_conflict), teardown, on_done({})
```

A conflict (during probing or while live) invokes `service_options::on_conflict`. If the callback returns a replacement name, probing restarts with it (rate-limited per §8.1). If it returns `std::nullopt` (or no callback is set), the server tears down: `on_ready` fires with `mdns_error::probe_conflict`, the full teardown runs (goodbye if applicable), and `on_done` fires with `std::error_code{}`.

### Threading and callback contract

- All callbacks (`on_ready`, `on_done`, `on_conflict`, `on_query`, `on_tc_continuation`, `on_error`) fire on the executor.
- A callback may call `stop()`; it must NOT destroy the server from within itself.
- `stop()` and destruction complete a pending `on_ready` with `std::errc::operation_canceled` (when not yet live) and always complete `on_done` — pending handlers are never silently dropped.

## Supporting Types

### service_info

```cpp
struct service_info {
    dns_name                   service_name;   // e.g. "MyApp._http._tcp.local."
    dns_name                   service_type;   // e.g. "_http._tcp.local."
    dns_name                   hostname;       // e.g. "myhost.local."
    uint16_t                   port{0};
    uint16_t                   priority{0};    // SRV priority (lower = preferred)
    uint16_t                   weight{0};      // SRV weight (load balancing)
    std::optional<std::string> address_ipv4;   // e.g. "192.168.1.10"
    std::optional<std::string> address_ipv6;   // e.g. "fe80::1"
    std::vector<service_txt>   txt_records;    // RFC 6763 key/value entries
    std::vector<std::string>   subtypes;       // e.g. {"_printer"} for subtype enumeration
    bool                       auto_address{false}; // set by make(); see service_info docs
};
```

Defined in `<mdnspp/service_info.h>`; full reference in [service_info](service_info.md). Describes the service to announce. The `subtypes` field lists DNS-SD subtype labels (RFC 6763 section 7.1) for subtype-filtered discovery and optional subtype announcement (see `service_options::announce_subtypes`).

The validated factory `service_info::make()` derives `service_name`, `service_type`, and `hostname` from an instance label and a service type, and sets `auto_address`: the server then resolves the unset `address_ipv4` / `address_ipv6` fields from the announcing interface at `async_start` and after every `update_service_info()` (RFC 6762 section 6.2; see [service_info](service_info.md)):

```cpp
auto info = mdnspp::service_info::make("MyApp", "_http._tcp", 8080);
```

Alternatively, use C++20 designated initializers for the fully explicit form:

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
using query_callback = move_only_function<void(const endpoint&, dns_type, response_mode)>;
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
                  << " (" << to_string(mode) << ")" << std::endl;
    };

    mdnspp::service_server srv{ctx, std::move(info), std::move(opts)};

    std::thread shutdown{[&srv] {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        srv.stop(); // safe from any thread; goodbye is sent on the executor
    }};

    std::cout << "Serving MyApp._http._tcp.local. on port 8080 (30s then auto-stop)" << std::endl;
    srv.async_start(
        [](std::error_code ec)
        {
            if (ec)
                std::cerr << "start failed: " << ec.message() << std::endl;
        },
        [&ctx](std::error_code)
        {
            ctx.stop(); // teardown complete, goodbye sent
        });
    ctx.run();

    shutdown.join();
}
```

## Multiple Servers on One Context

Multiple `service_server` instances can share the same executor. Each server
creates its own socket, and the context multiplexes all of them. This works
with both default_policy and asio_policy.

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
- [mdns_options](mdns_options.md) -- TC accumulation, known-answer suppression, query backoff tunables
- [service_discovery](service_discovery.md) -- discover services announced by servers
- [resolved_service](resolved_service.md) -- the aggregated service type
- [observer](observer.md) -- passively listen to all mDNS traffic
- [Socket Options](../socket-options.md) -- network interface selection, multicast TTL, loopback control
- [tc-handling](../rfc/tc-handling.md) -- RFC 6762 §6 truncated-response accumulation
- [duplicate-suppression](../rfc/duplicate-suppression.md) -- RFC 6762 §7.4 known-answer suppression
