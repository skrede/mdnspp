# TXT Record Key-Value Pairs

RFC 6763 §6 defines the format and semantics of DNS-SD TXT records. A TXT record
associated with a service instance carries zero or more key-value pairs that describe
service attributes: version numbers, configuration flags, paths, and other metadata.
Each pair is length-prefixed on the wire; keys are case-insensitive ASCII strings and
values are arbitrary byte sequences.

**RFC Reference:** RFC 6763 §6

## Example

Add TXT records when constructing a service. Access them from a resolved service:

```cpp
#include <mdnspp/defaults.h>
#include <mdnspp/service_info.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    // Announce a service with TXT key-value pairs
    mdnspp::service_info info{
        .service_name = "MyApp._http._tcp.local.",
        .service_type = "_http._tcp.local.",
        .hostname     = "myhost.local.",
        .port         = 8080,
        .address_ipv4 = "192.168.1.42",
        .txt_records  = {
            {"path",    "/api"},     // key=value pair
            {"version", "2"},        // key=value pair
            {"secure",  {}},         // key-only entry (no value)
        },
    };

    mdnspp::service_server srv{ctx, std::move(info)};
    srv.async_start();

    // Discover services and read their TXT records
    mdnspp::monitor_options mon_opts{
        .on_found = [](const mdnspp::resolved_service &svc)
        {
            std::cout << "found: " << svc.instance_name << std::endl;
            for(const auto &txt : svc.txt_entries)
            {
                std::cout << "  " << txt.key;
                if(txt.value)
                    std::cout << "=" << *txt.value;
                std::cout << std::endl;
            }
        },
    };

    mdnspp::service_monitor mon{ctx, std::move(mon_opts)};
    mon.watch("_http._tcp.local.");
    mon.async_start();

    ctx.run();
}
```

TXT records are stored as `std::vector<service_txt>` in both `service_info::txt_records`
(for announcing) and `resolved_service::txt_entries` (for discovered services).

## Compliance Status

| Status | Aspect | Notes |
|--------|--------|-------|
| Implemented | TXT key-value pair encoding | Length-prefixed `key=value` entries on wire |
| Implemented | Key-only entries | Entries without a `=` character; `service_txt::value` is `std::nullopt` |
| Implemented | TXT record parsing | `record_txt::entries` populated from wire format |
| Implemented | TXT record in service_info | `service_info::txt_records` passed to service_server |
| Implemented | TXT correlation in resolved_service | `resolved_service::txt_entries` populated by aggregate() |
| Implemented | TXT deduplication by key | Latest TXT value wins when the same key appears more than once |
| Implemented | Empty TXT as single zero byte (RFC 6763 §6.1) | A service with no TXT entries is announced with rdata consisting of one zero byte, never `RDLENGTH=0`; the TXT record is always present in PTR/ANY responses |
| Partial | Zero-length string handling (RFC 6763 §6.4) | Strings starting with `=` (no key) are skipped on parse; a zero-length string currently yields an entry with an empty key rather than being ignored |

## In-Depth

### Wire format

Each TXT record is a DNS `RDATA` field containing one or more length-prefixed strings.
Each string has the form:
```
<length byte> <key> ["=" <value bytes>]
```

- The length byte counts the total bytes in the string (key + optional "=" + value).
- The maximum length per string is 255 bytes.
- A record with no entries is encoded as a single zero byte (RFC 6763 §6.1); `RDLENGTH=0` is never emitted.
- On parse, strings beginning with `=` (separator with no key) are skipped; a zero-length string currently yields an entry with an empty key.
- Keys are case-insensitive per RFC 6763 §6.4.

### Key-only entries

An entry without a `=` character (or with a zero-length value after `=`) indicates
the presence of a boolean feature flag. In mdnspp, a key-only entry is represented by
`service_txt::value == std::nullopt`.

### service_txt struct

```cpp
struct service_txt {
    std::string key;
    std::optional<std::string> value;
};
```

Used in both `service_info::txt_records` (outgoing) and `resolved_service::txt_entries`
(incoming, after parsing and correlation).

### TXT record deduplication

When the cache accumulates multiple TXT records for the same service instance,
`aggregate()` merges them by key: the latest value for each key wins. This matches
RFC 6763 §6.4, which states that duplicate keys should not appear but prescribes
last-writer-wins behavior for resolvers that encounter them.

## See Also

- [service_info](../api/service_options.md) — service declaration including TXT records
- [resolved_service](../api/resolved_service.md) — discovered service with `txt_entries`
- [dns-sd](dns-sd.md) — DNS-SD subtype queries and enumeration
- [RFC Compliance](README.md)
