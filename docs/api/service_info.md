# service_info

`service_info` describes an mDNS service to announce. It is passed to
[`service_server`](service_server.md) (and to `nic_group` through
`server_peer_options::info`) and determines the PTR, SRV, TXT, and A/AAAA
records the responder publishes (RFC 6762 / RFC 6763).

**Header:**

```cpp
#include <mdnspp/service_info.h>
```

Included transitively by `#include <mdnspp/defaults.h>`.

## Struct

```cpp
namespace mdnspp {

struct service_info
{
    dns_name service_name;                   // e.g. "MyApp._http._tcp.local."
    dns_name service_type;                   // e.g. "_http._tcp.local."
    dns_name hostname;                       // e.g. "myhost.local."
    uint16_t port{0};
    uint16_t priority{0};
    uint16_t weight{0};
    std::optional<std::string> address_ipv4; // e.g. "192.168.1.10"
    std::optional<std::string> address_ipv6; // e.g. "fe80::1"
    std::vector<service_txt> txt_records;
    std::vector<std::string> subtypes;
    bool auto_address{false};

    [[nodiscard]] static expected<service_info, mdns_error>
    make(std::string_view instance, std::string_view service_type,
         uint16_t port, service_make_options opts = {});
};

}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `service_name` | `dns_name` | Fully-qualified service instance name (PTR target, SRV/TXT owner). |
| `service_type` | `dns_name` | Service type (PTR owner), e.g. `"_http._tcp.local."`. |
| `hostname` | `dns_name` | Target hostname for SRV/A/AAAA records. |
| `port` | `uint16_t` | TCP/UDP port carried in the SRV record. |
| `priority` | `uint16_t` | SRV priority (lower = more preferred). |
| `weight` | `uint16_t` | SRV weight (load balancing among equal-priority targets). |
| `address_ipv4` | `std::optional<std::string>` | IPv4 address for the A record. Unset: no A record (unless `auto_address`). |
| `address_ipv6` | `std::optional<std::string>` | IPv6 address for the AAAA record. Unset: no AAAA record (unless `auto_address`). |
| `txt_records` | `std::vector<service_txt>` | RFC 6763 TXT key/value pairs; key-only entries have no value. |
| `subtypes` | `std::vector<std::string>` | DNS-SD subtype labels (RFC 6763 section 7.1), e.g. `{"_printer"}`. |
| `auto_address` | `bool` | Set by `make()`: the server resolves the unset address fields at `async_start` (see below). Aggregate initialization leaves it `false`, preserving the omit-when-unset semantics. |

## make()

```cpp
[[nodiscard]] static expected<service_info, mdns_error>
make(std::string_view instance, std::string_view service_type,
     uint16_t port, service_make_options opts = {});
```

Builds a validated `service_info` from an unescaped instance label and a
service type:

- `instance` is an unescaped UTF-8 instance label. `'.'` and `'\'` are
  escaped per RFC 1035 §5.1 (`"Dr. Smith"` becomes the single label
  `Dr\. Smith`), as RFC 6763 §4.3 requires of DNS-SD APIs. Byte case and
  UTF-8 sequences are preserved.
- `service_type` is `"_http._tcp"` or `"_http._tcp.local."`; `".local."` is
  appended when the input carries no domain. The trailing dot is optional in
  all forms. The result is validated with `parse_service_type_checked()`.
- `port` is the SRV port; `0` is rejected.
- `service_name` is the escaped instance label joined with the normalized
  type; `hostname` is derived as described under
  [`service_make_options`](#service_make_options).

### Errors

| Condition | Error |
|-----------|-------|
| Structurally invalid service type (missing type, protocol, or domain label) | `mdns_error::invalid_name` |
| Instance label or hostname failing `dns_name::parse()` (empty label, label over 63 octets, name over 255 octets) | `mdns_error::invalid_name` |
| Unusable OS host name (empty, or not a valid label) | `mdns_error::invalid_name` |
| `port == 0` | `mdns_error::invalid_argument` |

## service_make_options

```cpp
namespace mdnspp {

struct service_make_options
{
    std::optional<std::string> hostname{};
    uint16_t priority{0};
    uint16_t weight{0};
    std::optional<std::string> address_ipv4{};
    std::optional<std::string> address_ipv6{};
    bool advertise_addresses{true};
    std::vector<service_txt> txt_records{};
    std::vector<std::string> subtypes{};
};

}
```

| Field | Default | Description |
|-------|---------|-------------|
| `hostname` | unset | Hostname override: a single label or a name ending in `".local"` (trailing dot optional); the `".local."` suffix is appended when missing, ASCII case-insensitively detected. Unset: the OS host name (`::gethostname`), stripped of any domain part and suffixed with `".local."`. |
| `priority` | `0` | SRV priority. |
| `weight` | `0` | SRV weight. |
| `address_ipv4` | unset | Explicit IPv4 address. Left unset, the address is resolved at `async_start` (see below). |
| `address_ipv6` | unset | Explicit IPv6 address. Left unset, the address is resolved at `async_start` (see below). |
| `advertise_addresses` | `true` | `false`: no A/AAAA records are announced — both address fields are cleared and `auto_address` stays `false`. |
| `txt_records` | empty | RFC 6763 TXT entries. |
| `subtypes` | empty | DNS-SD subtype labels. |

## Address auto-detection (auto_address)

RFC 6762 §6.2 requires the advertised addresses to be valid on the link the
records are announced on. `make()` therefore leaves unset address fields to
be resolved by the server rather than guessing at construction time: it sets
`auto_address` when `advertise_addresses` is `true` and at least one address
field is unset. Fields the caller set explicitly are never overwritten —
auto-detection fills only the unset fields.

At `async_start` (and again after every `update_service_info()` carrying an
`auto_address` info), `basic_service_server` fills each unset field as
follows:

1. When the socket is bound to a specific interface
   (`socket_options::interface_index`, `interface_name`, or
   `interface_address` — see [Socket Options](../socket-options.md)), the
   bound interface's address of the respective family is used. An interface
   without an address of a family leaves that family unset; addresses of
   other interfaces are never substituted.
2. When bound by `interface_address` to an address absent from
   `enumerate_interfaces()`, the bound address itself is used for its
   family.
3. Unbound, the address of the non-loopback, running interface with the
   lowest OS interface index that has an address of the respective family is
   used (a deterministic rule across calls).

A family with no candidate stays unset and its records are simply not
announced (e.g. AAAA on an IPv6-less host) — this is not an error.

## Example

```cpp
auto info = mdnspp::service_info::make("MyApp", "_http._tcp", 8080,
                                       {.txt_records = {{"path", "/index.html"}}});
if(!info.has_value())
    return; // mdns_error::invalid_name or mdns_error::invalid_argument

mdnspp::service_server srv{ctx, std::move(*info)};
```

The aggregate form remains the fully explicit alternative; addresses are
then announced exactly as given and unset fields are omitted:

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

## See also

- [service_server](service_server.md) — the responder consuming `service_info`
- [service_options](service_options.md) — probing, announcing, and conflict configuration
- [Socket Options](../socket-options.md) — interface selection feeding the auto-detection rule
- [Errors](errors.md) — `mdns_error` reference
