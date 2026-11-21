# records

The parsed mDNS resource records delivered by the observer, querier, discovery
and cache APIs, the `mdns_record_variant` that holds them, and the DNS
vocabulary enums.

## Header

```cpp
#include <mdnspp/records.h>
#include <mdnspp/dns.h>      // operator<< for dns_type and dns_class
```

`<mdnspp/records.h>` is included transitively by every `basic_*` header.

## Record structs

```cpp
namespace mdnspp {

struct record_ptr  { static constexpr dns_type rtype = dns_type::ptr;  /* common fields */ dns_name ptr_name; };
struct record_srv  { static constexpr dns_type rtype = dns_type::srv;  /* common fields */
                     uint16_t port{0}; uint16_t weight{0}; uint16_t priority{0}; dns_name srv_name; };
struct record_a    { static constexpr dns_type rtype = dns_type::a;    /* common fields */ std::string address_string; };
struct record_aaaa { static constexpr dns_type rtype = dns_type::aaaa; /* common fields */ std::string address_string; };
struct record_txt  { static constexpr dns_type rtype = dns_type::txt;  /* common fields */ std::vector<service_txt> entries; };

using mdns_record_variant = std::variant<record_ptr, record_srv, record_a, record_aaaa, record_txt>;

dns_type record_type(const mdns_record_variant &rec);

}
```

Every record struct is an aggregate with a defaulted `operator==` and starts with
the same common fields:

| Field | Type | Description |
|-------|------|-------------|
| `name` | `dns_name` | Owner name of the record. |
| `ttl` | `uint32_t` | TTL from the wire, in seconds. |
| `rclass` | `dns_class` | Record class with the cache-flush bit removed. |
| `length` | `uint32_t` | RDLENGTH from the wire. |
| `sender_address` | `std::string` | Address of the host that sent the packet. |
| `cache_flush` | `bool` | The cache-flush bit of the class field (RFC 6762 §10.2). |

Type-specific fields:

| Struct | Field | Description |
|--------|-------|-------------|
| `record_ptr` | `ptr_name` | PTR target, e.g. a service instance name. |
| `record_srv` | `port`, `weight`, `priority`, `srv_name` | SRV data (RFC 2782); `srv_name` is the target host. |
| `record_a` | `address_string` | IPv4 address in dotted-decimal form, e.g. `"192.168.1.1"`. |
| `record_aaaa` | `address_string` | IPv6 address in colon-hex form, e.g. `"fe80::1"`. |
| `record_txt` | `entries` | TXT key/value pairs (RFC 6763 §6), see `service_txt` below. |

## record_type

```cpp
dns_type record_type(const mdns_record_variant &rec);
```

Returns the `dns_type` of the alternative `rec` currently holds (the `rtype` of its
struct), so a record's type can be checked without `std::visit`:

```cpp
if(mdnspp::record_type(rec) == mdnspp::dns_type::srv)
    handle(std::get<mdnspp::record_srv>(rec));
```

## service_txt

```cpp
struct service_txt
{
    std::string key;
    std::optional<std::string> value;
};
```

One RFC 6763 TXT entry. A key-only entry (a boolean attribute) has
`value == std::nullopt`; `key=` with an empty value has an engaged, empty `value`.

## Stream output

`operator<<` is provided for each record struct (sender, type, owner name, data,
class, TTL and length on one line) and, through `<mdnspp/dns.h>`, for `dns_type`
and `dns_class`. An enum value without a name prints as `unknown(N)` with its
numeric value.

## See Also

- [dns_name](dns_name.md) &mdash; the name type of `name`, `ptr_name` and `srv_name`
- [cache_entry](cache_entry.md) &mdash; cached records with remaining TTL
- [resolved_service](resolved_service.md) &mdash; records aggregated into services
- [TXT Records](../rfc/txt-records.md) &mdash; TXT parsing rules
