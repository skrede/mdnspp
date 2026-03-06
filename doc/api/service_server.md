# service_server

Announces an mDNS service on the local network and responds to matching queries with DNS records. Implements RFC 6762 random response delay (20--500 ms) for multicast responses and supports unicast responses when the QU bit is set.

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
using query_callback     = std::move_only_function<void(const endpoint&, dns_type, bool)>;
using completion_handler = std::move_only_function<void(std::error_code)>;
```

## Constructors

### Throwing

```cpp
explicit basic_service_server(executor_type ex, service_info info,
                              query_callback on_query = {});
```

Constructs the server from an executor, a [`service_info`](#service_info) describing the service to announce, and an optional callback invoked when a matching query is received. Throws on socket construction failure.

### Non-throwing

```cpp
basic_service_server(executor_type ex, service_info info,
                     query_callback on_query, std::error_code& ec);

basic_service_server(executor_type ex, service_info info, std::error_code& ec);
```

Same as the throwing constructor, but sets `ec` instead of throwing on failure.

## Methods

### async_start

```cpp
void async_start(completion_handler on_done = {});
```

Arms the internal receive loop and returns immediately. The server begins listening for mDNS queries that match the configured service name, type, or hostname. Matching queries trigger RFC 6762-delayed responses.

The `on_done` handler fires with `std::error_code{}` when `stop()` is called.

Must only be called once per lifetime.

### stop

```cpp
void stop();
```

Idempotent. Fires the completion handler, cancels the response timer, and destroys the receive loop. The destructor calls `stop()` automatically for RAII safety.

### Accessors

```cpp
const socket_type& socket()     const noexcept;
      socket_type& socket()           noexcept;
const timer_type&  timer()      const noexcept;  // response delay timer
      timer_type&  timer()            noexcept;
const timer_type&  recv_timer() const noexcept;  // receive loop timer
      timer_type&  recv_timer()       noexcept;
```

The server uses two timers: `timer()` for the RFC 6762 random response delay, and `recv_timer()` for the internal receive loop.

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
};
```

Defined in `<mdnspp/service_info.h>`. Describes the service to announce. Use C++20 designated initializers for readability:

```cpp
mdnspp::service_info info{
    .service_name = "MyApp._http._tcp.local.",
    .service_type = "_http._tcp.local.",
    .hostname     = "myhost.local.",
    .port         = 8080,
    .address_ipv4 = "192.168.1.10",
    .txt_records  = {{"path", "/index.html"}},
};
```

### query_callback

```cpp
using query_callback = std::move_only_function<void(const endpoint&, dns_type, bool)>;
```

Called when a matching mDNS query is received. Parameters:

| Parameter | Type | Description |
|-----------|------|-------------|
| `sender` | `endpoint` | The querier's address and port |
| `qtype` | `dns_type` | The record type requested (PTR, SRV, A, etc.) |
| `unicast` | `bool` | `true` if the QU bit was set (RFC 6762 section 5.4) |

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
#include <mdnspp/detail/dns_enums.h>

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

    mdnspp::service_server srv{ctx, std::move(info),
        [](const mdnspp::endpoint& sender, mdnspp::dns_type qtype, bool unicast)
        {
            std::cout << sender << " queried qtype=" << to_string(qtype)
                      << (unicast ? " (unicast)" : " (multicast)") << "\n";
        }
    };

    std::thread shutdown{[&ctx] {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        ctx.stop();  // ctx.stop() ends ctx.run()
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

- [service_discovery](service_discovery.md) -- discover services announced by servers
- [resolved_service](resolved_service.md) -- the aggregated service type
- [observer](observer.md) -- passively listen to all mDNS traffic
