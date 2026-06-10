# service_options

## Overview

`service_options` controls the behavior of a service server during its
lifecycle: probing for name uniqueness, announcing the service, sending
goodbye packets on shutdown, suppressing responses when the querier already
knows the answer, responding to DNS-SD meta-queries, announcing subtypes,
and handling name conflicts. All fields have RFC-compliant defaults -- construct
a server with `service_options{}` and the server probes, announces twice at
one-second intervals, sends goodbye on stop, suppresses known answers, and
responds to meta-queries.

Options are validated at server construction: invalid combinations (zero
`probe_count`, non-positive intervals or TTLs, empty or invalid service
names) fail with `std::errc::invalid_argument` -- thrown as
`std::system_error` from the throwing constructor, or reported through the
`std::error_code` overload.

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
    using conflict_callback = move_only_function<
        std::optional<std::string>(std::string_view conflicting_name, uint32_t attempt, conflict_type type)>;

    conflict_callback on_conflict{};
    move_only_function<void(const endpoint &sender, dns_type type, response_mode mode)> on_query{};
    move_only_function<void(const endpoint &sender, std::size_t continuation_count)> on_tc_continuation{};
    move_only_function<void(std::error_code ec, std::string_view context)> on_error{};
    uint8_t announce_count{2};
    std::chrono::milliseconds announce_interval{1000};
    bool send_goodbye{true};
    bool suppress_known_answers{true};
    bool respond_to_meta_queries{true};
    bool announce_subtypes{false};
    uint8_t probe_count{3};
    std::chrono::milliseconds probe_interval{250};
    std::chrono::milliseconds probe_initial_delay_max{250};
    bool respond_to_legacy_unicast{true};
    std::chrono::seconds ptr_ttl{4500};
    std::chrono::seconds srv_ttl{120};
    std::chrono::seconds txt_ttl{4500};
    std::chrono::seconds a_ttl{120};
    std::chrono::seconds aaaa_ttl{120};
    std::chrono::seconds fallback_record_ttl{4500};
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
| `on_error` | `move_only_function<void(std::error_code, std::string_view)>` | `{}` (none) | -- | Called on fire-and-forget send failures and address encoding errors. Receives the `std::error_code` and a context string identifying the failure site. |
| `announce_count` | `uint8_t` | `2` | RFC 6762 §8.3 | Number of announcement packets sent after probing completes. Also controls the number of announcements sent by `update_service_info()`. |
| `announce_interval` | `std::chrono::milliseconds` | `1000ms` | RFC 6762 §8.3 | Interval between consecutive announcement packets. |
| `send_goodbye` | `bool` | `true` | RFC 6762 §10.1 | Whether to send a goodbye packet (TTL=0) on `stop()`. |
| `suppress_known_answers` | `bool` | `true` | RFC 6762 §7.1 | Whether to suppress responses when the querier includes matching known answers with TTL at least half of the default. |
| `respond_to_meta_queries` | `bool` | `true` | RFC 6763 §9 | Whether to respond to DNS-SD service type enumeration queries (`_services._dns-sd._udp.local.`). |
| `announce_subtypes` | `bool` | `false` | RFC 6763 §7.1 | Whether to include subtype PTR records in announcement bursts. |
| `probe_count` | `uint8_t` | `3` | RFC 6762 §8.1 | Number of probe packets sent before a service is considered conflict-free and announcing begins. Values below 1 skip probing entirely, which is non-compliant. |
| `probe_interval` | `std::chrono::milliseconds` | `250ms` | RFC 6762 §8.1 | Interval between successive probe packets. |
| `probe_initial_delay_max` | `std::chrono::milliseconds` | `250ms` | RFC 6762 §8.1 | Upper bound on the random initial delay before the first probe is sent. The first probe is delayed by a uniform random value in `[0, probe_initial_delay_max]` to desynchronize simultaneous startups. |
| `respond_to_legacy_unicast` | `bool` | `true` | RFC 6762 §6.7 | Whether to respond to legacy unicast queries (source port != 5353). When enabled, the responder sends a unicast reply with TTLs capped at `mdns_options::legacy_unicast_ttl`. |
| `ptr_ttl` | `std::chrono::seconds` | `4500s` | RFC 6762 §10 | TTL for PTR records in outgoing responses. |
| `srv_ttl` | `std::chrono::seconds` | `120s` | RFC 6762 §10 | TTL for SRV records in outgoing responses. SRV rdata contains a host name; §10 recommends 120 s for host-name-containing records. |
| `txt_ttl` | `std::chrono::seconds` | `4500s` | RFC 6762 §10 | TTL for TXT records in outgoing responses. |
| `a_ttl` | `std::chrono::seconds` | `120s` | RFC 6762 §10 | TTL for A records in outgoing responses. A records name a host; §10 recommends 120 s. |
| `aaaa_ttl` | `std::chrono::seconds` | `120s` | RFC 6762 §10 | TTL for AAAA records in outgoing responses. Same rationale as `a_ttl`. |
| `fallback_record_ttl` | `std::chrono::seconds` | `4500s` | RFC 6762 §10 | Fallback TTL used for NSEC and meta-query PTR records when no per-record-type TTL is applicable. |
| `probe_authority_ttl` | `std::chrono::seconds` | `120s` | RFC 6762 §8.2 | TTL for SRV records placed in the authority section of probe queries for simultaneous-probe tiebreaking. This value is not cached by recipients; changing it has no interoperability impact. |
| `probe_defer_delay` | `std::chrono::milliseconds` | `1000ms` | RFC 6762 §8.2 | Delay before re-probing after losing a simultaneous-probe tiebreak. When the tiebreaking comparison indicates the remote probe wins, the local node defers by this duration before restarting its probe sequence. |

### on_conflict

Called when probing detects a name conflict, or when post-probe conflict
monitoring (RFC 6762 §9) observes another responder asserting different
rdata for the server's unique names. The callback receives the conflicting
name, the current attempt number (starting at 0), and a `conflict_type`
value indicating whether this is a name conflict or a tiebreak deferral.
Return the replacement service instance name to retry probing with it, or
`std::nullopt` to give up. Giving up tears the server down: `on_ready`
fires with `mdns_error::probe_conflict`, the full teardown runs, and
`on_done` then fires with `std::error_code{}`.

When no callback is set, the server gives up immediately on conflict.

Probing is rate-limited per RFC 6762 §8.1: after fifteen conflicts within
ten seconds, the server waits five seconds before the next probe attempt.

**RFC reference:** RFC 6762 section 8.1 (probing), section 8.2 (tiebreaking), section 9 (conflict resolution).

```cpp
mdnspp::service_options opts;
opts.on_conflict = [](std::string_view name, uint32_t attempt,
                      mdnspp::conflict_type type) -> std::optional<std::string>
{
    if (attempt >= 3)
        return std::nullopt; // give up after 3 retries
    auto dot = name.find('.');
    return std::string(name.substr(0, dot)) + "-" + std::to_string(attempt + 2)
         + std::string(name.substr(dot));
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
    std::cout << sender << " queried " << to_string(qtype) << std::endl;
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
    std::cout << "TC from " << sender << ": " << count << " continuation packet(s)" << std::endl;
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
using conflict_callback = move_only_function<
    std::optional<std::string>(std::string_view conflicting_name, uint32_t attempt, conflict_type type)>;
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `conflicting_name` | `std::string_view` | The service name that conflicted. |
| `attempt` | `uint32_t` | Zero-based attempt counter. |
| `type` | `conflict_type` | `conflict_type::name_conflict` for a straightforward name clash; `conflict_type::tiebreak_deferred` when the local probe lost a simultaneous-probe tiebreak (RFC 6762 §8.2). |
| **Return** | `std::optional<std::string>` | The replacement service instance name to retry probing with, or `std::nullopt` to give up. |

When the callback returns `std::nullopt` (or no callback is set), the
server tears down: `on_ready` fires with `mdns_error::probe_conflict`,
then `on_done` fires with `std::error_code{}` after teardown completes.

**conflict_type values:**

| Value | When fired |
|-------|------------|
| `conflict_type::name_conflict` | Another host responded during the probe window owning the same name. |
| `conflict_type::tiebreak_deferred` | Two hosts probed simultaneously; the local record set lost the §8.2.1 lexicographic comparison (class, then type, then uncompressed rdata, over the full proposed record sets). An identical record set is not a conflict. |

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
opts.on_conflict = [](std::string_view name, uint32_t attempt,
                      mdnspp::conflict_type type) -> std::optional<std::string>
{
    if (attempt >= 3)
        return std::nullopt;
    // Append attempt number: "MyApp" -> "MyApp-2", "MyApp-3", ...
    auto dot = name.find('.');
    return std::string(name.substr(0, dot)) + "-" + std::to_string(attempt + 2)
         + std::string(name.substr(dot));
};

mdnspp::service_server srv{ctx, std::move(info), std::move(opts)};
srv.async_start(
    [](std::error_code ec) {
        if (ec == mdnspp::mdns_error::probe_conflict)
            std::cerr << "all conflict resolution attempts exhausted" << std::endl;
        else
            std::cout << "server is live" << std::endl;
    });
ctx.run();
```

### Full customization

```cpp
mdnspp::service_options opts;
opts.on_conflict = [](std::string_view name, uint32_t attempt,
                      mdnspp::conflict_type type) -> std::optional<std::string>
{
    if (attempt >= 5)
        return std::nullopt;
    auto dot = name.find('.');
    return std::string(name.substr(0, dot)) + "-" + std::to_string(attempt + 2)
         + std::string(name.substr(dot));
};
opts.on_query = [](const mdnspp::endpoint &sender, mdnspp::dns_type qtype, mdnspp::response_mode mode) {
    log_query(sender, qtype, mode);
};
opts.on_tc_continuation = [](const mdnspp::endpoint &sender, std::size_t count) {
    log_tc(sender, count);
};
opts.on_error = [](std::error_code ec, std::string_view context) {
    log_error(ec, context);
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
