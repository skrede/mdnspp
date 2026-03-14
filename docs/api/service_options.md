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
    using conflict_callback = detail::move_only_function<
        bool(const std::string &conflicting_name, std::string &new_name,
             unsigned attempt, conflict_type type)>;

    conflict_callback on_conflict{};
    detail::move_only_function<void(const endpoint &sender, dns_type type, response_mode mode)> on_query{};
    detail::move_only_function<void(const endpoint &sender, std::size_t continuation_count)> on_tc_continuation{};
    unsigned announce_count{2};
    std::chrono::milliseconds announce_interval{1000};
    bool send_goodbye{true};
    bool suppress_known_answers{true};
    bool respond_to_meta_queries{true};
    bool announce_subtypes{false};
    unsigned probe_count{3};
    std::chrono::milliseconds probe_interval{250};
    std::chrono::milliseconds probe_initial_delay_max{250};
    bool respond_to_legacy_unicast{true};
    std::chrono::seconds ptr_ttl{4500};
    std::chrono::seconds srv_ttl{4500};
    std::chrono::seconds txt_ttl{4500};
    std::chrono::seconds a_ttl{4500};
    std::chrono::seconds aaaa_ttl{4500};
    std::chrono::seconds record_ttl{4500};
    std::chrono::seconds probe_authority_ttl{120};
    std::chrono::milliseconds probe_defer_delay{1000};
};

}
```

## Fields

| Field | Type | Default | RFC Section | Description |
|-------|------|---------|-------------|-------------|
| `on_conflict` | `conflict_callback` | `{}` (none) | RFC 6762 §8.1, §9 | Called when a name conflict is detected during probing. See [conflict_callback](#conflict_callback) for signature and parameters. |
| `on_query` | `move_only_function<void(const endpoint&, dns_type, response_mode)>` | `{}` (none) | RFC 6762 §5.4 | Called when a matching query is received while live. |
| `on_tc_continuation` | `move_only_function<void(const endpoint&, std::size_t)>` | `{}` (none) | RFC 6762 §6 | Fired when a TC continuation is processed. Reports the sender endpoint and the number of accumulated continuation packets. |
| `announce_count` | `unsigned` | `2` | RFC 6762 §8.3 | Number of announcement packets sent after probing completes. Also controls the number of announcements sent by `update_service_info()`. |
| `announce_interval` | `std::chrono::milliseconds` | `1000ms` | RFC 6762 §8.3 | Interval between consecutive announcement packets. |
| `send_goodbye` | `bool` | `true` | RFC 6762 §10.1 | Whether to send a goodbye packet (TTL=0) on `stop()`. |
| `suppress_known_answers` | `bool` | `true` | RFC 6762 §7.1 | Whether to suppress responses when the querier includes matching known answers with TTL at least half of the default. |
| `respond_to_meta_queries` | `bool` | `true` | RFC 6763 §9 | Whether to respond to DNS-SD service type enumeration queries (`_services._dns-sd._udp.local.`). |
| `announce_subtypes` | `bool` | `false` | RFC 6763 §7.1 | Whether to include subtype PTR records in announcement bursts. |
| `probe_count` | `unsigned` | `3` | RFC 6762 §8.1 | Number of probe packets sent before a service is considered conflict-free and announcing begins. Values below 1 skip probing entirely, which is non-compliant. |
| `probe_interval` | `std::chrono::milliseconds` | `250ms` | RFC 6762 §8.1 | Interval between successive probe packets. |
| `probe_initial_delay_max` | `std::chrono::milliseconds` | `250ms` | RFC 6762 §8.1 | Upper bound on the random initial delay before the first probe is sent. The first probe is delayed by a uniform random value in `[0, probe_initial_delay_max]` to desynchronize simultaneous startups. |
| `respond_to_legacy_unicast` | `bool` | `true` | RFC 6762 §6.7 | Whether to respond to legacy unicast queries (source port != 5353). When enabled, the responder sends a unicast reply with TTLs capped at `mdns_options::legacy_unicast_ttl`. |
| `ptr_ttl` | `std::chrono::seconds` | `4500s` | RFC 6762 §11.3 | TTL for PTR records in outgoing responses. |
| `srv_ttl` | `std::chrono::seconds` | `4500s` | RFC 6762 §11.3 | TTL for SRV records in outgoing responses. |
| `txt_ttl` | `std::chrono::seconds` | `4500s` | RFC 6762 §11.3 | TTL for TXT records in outgoing responses. |
| `a_ttl` | `std::chrono::seconds` | `4500s` | RFC 6762 §11.3 | TTL for A records in outgoing responses. |
| `aaaa_ttl` | `std::chrono::seconds` | `4500s` | RFC 6762 §11.3 | TTL for AAAA records in outgoing responses. |
| `record_ttl` | `std::chrono::seconds` | `4500s` | RFC 6762 §11.3 | Fallback TTL used for NSEC and meta-query PTR records when no per-record-type TTL is applicable. |
| `probe_authority_ttl` | `std::chrono::seconds` | `120s` | RFC 6762 §8.2 | TTL for SRV records placed in the authority section of probe queries for simultaneous-probe tiebreaking. This value is not cached by recipients; changing it has no interoperability impact. |
| `probe_defer_delay` | `std::chrono::milliseconds` | `1000ms` | RFC 6762 §8.2 | Delay before re-probing after losing a simultaneous-probe tiebreak. When the tiebreaking comparison indicates the remote probe wins, the local node defers by this duration before restarting its probe sequence. |

### on_conflict

Called during probing when another responder already owns the service name.
The callback receives the conflicting name, a mutable reference to a new
name string, the current attempt number (starting at 0), and a
`conflict_type` value indicating whether this is a name conflict or a
tiebreak deferral. Return `true` to retry probing with the new name, or
`false` to give up (the server fires `on_ready` with
`mdns_error::probe_conflict`).

When no callback is set, the server gives up immediately on conflict.

**RFC reference:** RFC 6762 section 8.1 (probing), section 8.2 (tiebreaking), section 9 (conflict resolution).

```cpp
mdnspp::service_options opts;
opts.on_conflict = [](const std::string &name, std::string &new_name,
                      unsigned attempt, mdnspp::conflict_type type) -> bool
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
or hostname while the server is in the live state.

**Default:** None (no notification on queries).

```cpp
mdnspp::service_options opts;
opts.on_query = [](const mdnspp::endpoint &sender, mdnspp::dns_type qtype, mdnspp::response_mode mode)
{
    std::cout << sender << " queried " << to_string(qtype) << "\n";
};
```

### on_tc_continuation

Called after a TC (truncated) continuation is fully accumulated. Reports the
sender endpoint and the number of continuation packets collected. Useful for
diagnosing large known-answer list processing.

**Default:** None (TC continuations are handled silently).

```cpp
mdnspp::service_options opts;
opts.on_tc_continuation = [](const mdnspp::endpoint &sender, std::size_t count)
{
    std::cout << "TC from " << sender << ": " << count << " continuation packet(s)\n";
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
using conflict_callback = detail::move_only_function<
    bool(const std::string &conflicting_name, std::string &new_name,
         unsigned attempt, conflict_type type)>;
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `conflicting_name` | `const std::string&` | The service name that conflicted. |
| `new_name` | `std::string&` | Output parameter -- set this to the desired new name. |
| `attempt` | `unsigned` | Zero-based attempt counter. |
| `type` | `conflict_type` | `conflict_type::name_conflict` for a straightforward name clash; `conflict_type::tiebreak_deferred` when the local probe lost a simultaneous-probe tiebreak (RFC 6762 §8.2). |
| **Return** | `bool` | `true` to retry probing with `new_name`, `false` to give up. |

When the callback returns `false` (or no callback is set), the server
transitions to `stopped` state and fires the `on_ready` handler with
`mdns_error::probe_conflict`.

**conflict_type values:**

| Value | When fired |
|-------|------------|
| `conflict_type::name_conflict` | Another host responded during the probe window owning the same name. |
| `conflict_type::tiebreak_deferred` | Two hosts probed simultaneously; the local SRV rdata lost the §8.2 lexicographic comparison. |

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
opts.on_conflict = [](const std::string &name, std::string &new_name,
                      unsigned attempt, mdnspp::conflict_type type) -> bool
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
opts.on_conflict = [](const std::string &name, std::string &new_name,
                      unsigned attempt, mdnspp::conflict_type type) -> bool
{
    new_name = name.substr(0, name.find('.')) + "-" + std::to_string(attempt + 2)
             + name.substr(name.find('.'));
    return attempt < 5;
};
opts.on_query = [](const mdnspp::endpoint &sender, mdnspp::dns_type qtype, mdnspp::response_mode mode) {
    log_query(sender, qtype, mode);
};
opts.on_tc_continuation = [](const mdnspp::endpoint &sender, std::size_t count) {
    log_tc(sender, count);
};
opts.announce_count = 3;
opts.announce_interval = std::chrono::milliseconds{500};
opts.send_goodbye = true;
opts.suppress_known_answers = true;
opts.respond_to_meta_queries = true;
opts.announce_subtypes = true;
opts.probe_count = 3;
opts.probe_interval = std::chrono::milliseconds{250};
opts.respond_to_legacy_unicast = true;

mdnspp::service_server srv{ctx, std::move(info), std::move(opts)};
```

## See Also

- [service_server](service_server.md) -- the server that uses `service_options`
- [Socket Options](../socket-options.md) -- network-level configuration
- [Policies](../policies.md) -- policy-based design and lifecycle
