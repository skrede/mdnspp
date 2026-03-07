# service_options

## Overview

`service_options` controls the behavior of a service server during its
lifecycle: probing for name uniqueness, announcing the service, sending
goodbye packets on shutdown, suppressing responses when the querier already
knows the answer, responding to DNS-SD meta-queries, announcing subtypes,
and handling name conflicts. All fields have sensible defaults -- construct
a server with `service_options{}` and the server probes, announces twice at
one-second intervals, sends goodbye on stop, suppresses known answers, and
responds to meta-queries.

**Header:**

```cpp
#include <mdnspp/service_options.h>
```

Included transitively by `#include <mdnspp/defaults.h>`.

## service_options struct

```cpp
namespace mdnspp {

struct service_options
{
    using conflict_callback = std::move_only_function<
        bool(const std::string &conflicting_name, std::string &new_name, unsigned attempt)>;

    conflict_callback on_conflict{};
    std::move_only_function<void(const endpoint &sender, dns_type type, response_mode mode)> on_query{};
    unsigned announce_count{2};
    std::chrono::milliseconds announce_interval{1000};
    bool send_goodbye{true};
    bool suppress_known_answers{true};
    bool respond_to_meta_queries{true};
    bool announce_subtypes{false};
};

}
```

## Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `on_conflict` | `conflict_callback` | `{}` (none) | Called when a name conflict is detected during probing. |
| `on_query` | `std::move_only_function<void(const endpoint&, dns_type, response_mode)>` | `{}` (none) | Called when a matching query is received while live. |
| `announce_count` | `unsigned` | `2` | Number of announcement packets sent after probing completes. |
| `announce_interval` | `std::chrono::milliseconds` | `1000` | Interval between consecutive announcement packets. |
| `send_goodbye` | `bool` | `true` | Whether to send a goodbye packet (TTL=0) on `stop()`. |
| `suppress_known_answers` | `bool` | `true` | Whether to suppress responses when the querier includes matching known answers. |
| `respond_to_meta_queries` | `bool` | `true` | Whether to respond to DNS-SD service type enumeration queries (`_services._dns-sd._udp.local.`). |
| `announce_subtypes` | `bool` | `false` | Whether to include subtype PTR records in announcement bursts. |

### on_conflict

Called during probing when another responder already owns the service name.
The callback receives the conflicting name, a mutable reference to a new
name string, and the current attempt number (starting at 0). Return `true`
to retry probing with the new name, or `false` to give up (the server fires
`on_ready` with `mdns_error::probe_conflict`).

When no callback is set, the server gives up immediately on conflict.

**RFC reference:** RFC 6762 section 8.1 (probing), section 9 (conflict resolution).

```cpp
mdnspp::service_options opts;
opts.on_conflict = [](const std::string &name, std::string &new_name, unsigned attempt) -> bool
{
    if (attempt >= 3)
        return false; // give up after 3 retries
    new_name = name.substr(0, name.find('.')) + "-" + std::to_string(attempt + 2)
             + name.substr(name.find('.'));
    return true;
};
```

### on_query

Called when an incoming mDNS query matches the server's service name, type,
or hostname while the server is in the live state. This is the same callback
that was previously passed as a constructor parameter in older API versions.

**Default:** None (no notification on queries).

```cpp
mdnspp::service_options opts;
opts.on_query = [](const mdnspp::endpoint &sender, mdnspp::dns_type qtype, mdnspp::response_mode mode)
{
    std::cout << sender << " queried " << to_string(qtype) << "\n";
};
```

### announce_count

Number of unsolicited announcements sent after probing completes
successfully. Each announcement contains all records (PTR, SRV, TXT,
A/AAAA). Also controls the number of announcements sent by
`update_service_info()`.

**Default:** `2` (RFC 6762 section 8.3 recommends at least two).

**RFC reference:** RFC 6762 section 8.3.

```cpp
mdnspp::service_options opts;
opts.announce_count = 3; // send 3 announcements instead of 2
```

### announce_interval

Time between consecutive announcement packets. The first announcement is
sent immediately after probing completes.

**Default:** `1000ms` (1 second).

**RFC reference:** RFC 6762 section 8.3.

```cpp
mdnspp::service_options opts;
opts.announce_interval = std::chrono::milliseconds{500}; // faster announcements
```

### send_goodbye

When `true`, `stop()` sends a goodbye packet (all records with TTL=0)
before tearing down the receive loop. This tells other hosts to flush cached
records immediately rather than waiting for TTL expiry.

**Default:** `true`.

**RFC reference:** RFC 6762 section 10.1.

```cpp
mdnspp::service_options opts;
opts.send_goodbye = false; // skip goodbye on shutdown
```

### suppress_known_answers

When `true`, the server checks the Answer section of incoming queries for
records the querier already knows (known-answer suppression). If all records
that would be sent are already known with a TTL at least half of the
default, the response is suppressed entirely.

**Default:** `true`.

**RFC reference:** RFC 6762 section 7.1.

```cpp
mdnspp::service_options opts;
opts.suppress_known_answers = false; // always respond, even to known answers
```

### respond_to_meta_queries

When `true`, the server responds to DNS-SD service type enumeration queries
(`_services._dns-sd._udp.local.`) with a PTR record pointing to its service
type. This allows discovery clients using `async_enumerate_types()` to find
the server's service type.

**Default:** `true`.

**RFC reference:** RFC 6763 section 9.

```cpp
mdnspp::service_options opts;
opts.respond_to_meta_queries = false; // hide from service type enumeration
```

### announce_subtypes

When `true`, announcement bursts also include subtype PTR records for each
entry in `service_info::subtypes`. Each subtype PTR record maps from
`_subtype._sub._service._tcp.local.` to the service instance name.

**Default:** `false`.

**RFC reference:** RFC 6763 section 7.1.

```cpp
mdnspp::service_options opts;
opts.announce_subtypes = true; // announce subtypes during announcement burst
```

## conflict_callback

```cpp
using conflict_callback = std::move_only_function<
    bool(const std::string &conflicting_name, std::string &new_name, unsigned attempt)>;
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `conflicting_name` | `const std::string&` | The service name that conflicted. |
| `new_name` | `std::string&` | Output parameter -- set this to the desired new name. |
| `attempt` | `unsigned` | Zero-based attempt counter. |
| **Return** | `bool` | `true` to retry probing with `new_name`, `false` to give up. |

When the callback returns `false` (or no callback is set), the server
transitions to `stopped` state and fires the `on_ready` handler with
`mdns_error::probe_conflict`.

## Usage Examples

### Minimal (all defaults)

```cpp
mdnspp::context ctx;

mdnspp::service_info info{
    .service_name = "MyApp._http._tcp.local.",
    .service_type = "_http._tcp.local.",
    .hostname     = "myhost.local.",
    .port         = 8080,
    .address_ipv4 = "192.168.1.10",
};

mdnspp::service_server srv{ctx, std::move(info)};
srv.async_start();
ctx.run();
```

### With conflict resolution

```cpp
mdnspp::context ctx;

mdnspp::service_info info{
    .service_name = "MyApp._http._tcp.local.",
    .service_type = "_http._tcp.local.",
    .hostname     = "myhost.local.",
    .port         = 8080,
    .address_ipv4 = "192.168.1.10",
};

mdnspp::service_options opts;
opts.on_conflict = [](const std::string &name, std::string &new_name, unsigned attempt) -> bool
{
    if (attempt >= 3)
        return false;
    // Append attempt number: "MyApp" -> "MyApp-2", "MyApp-3", ...
    auto dot = name.find('.');
    new_name = name.substr(0, dot) + "-" + std::to_string(attempt + 2) + name.substr(dot);
    return true;
};

mdnspp::service_server srv{ctx, std::move(info), std::move(opts)};
srv.async_start(
    [](std::error_code ec) {
        if (ec == mdnspp::mdns_error::probe_conflict)
            std::cerr << "all conflict resolution attempts exhausted\n";
        else
            std::cout << "server is live\n";
    });
ctx.run();
```

### Full customization

```cpp
mdnspp::service_options opts;
opts.on_conflict = my_conflict_handler;
opts.on_query = [](const mdnspp::endpoint &sender, mdnspp::dns_type qtype, mdnspp::response_mode mode) {
    log_query(sender, qtype, mode);
};
opts.announce_count = 3;
opts.announce_interval = std::chrono::milliseconds{500};
opts.send_goodbye = true;
opts.suppress_known_answers = true;
opts.respond_to_meta_queries = true;
opts.announce_subtypes = true;

mdnspp::service_server srv{ctx, std::move(info), std::move(opts)};
```

## See Also

- [service_server](service_server.md) -- the server that uses `service_options`
- [Socket Options](../socket-options.md) -- network-level configuration
- [Policies](../policies.md) -- policy-based design and lifecycle
