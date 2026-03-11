# cache_entry

Snapshot of a cached mDNS record with TTL and origin information.

## Header

```cpp
#include <mdnspp/cache_entry.h>
```

## Fields

```cpp
struct cache_entry {
    mdns_record_variant          record;
    endpoint                     origin;
    bool                         cache_flush{false};
    uint32_t                     wire_ttl{0};
    std::chrono::nanoseconds     ttl_remaining{};
};
```

| Field | Type | Description |
|-------|------|-------------|
| `record` | `mdns_record_variant` | The cached record. A `std::variant` over `record_a`, `record_aaaa`, `record_ptr`, `record_srv`, and `record_txt`. Use `std::visit` to inspect the concrete type. |
| `origin` | `endpoint` | The sender's address and port from which this record was received. |
| `cache_flush` | `bool` | Whether the cache-flush bit was set on this record (RFC 6762 §10.2). When true, this record asserts authority over the name/type: conflicting records from other origins will be flushed within one second. |
| `wire_ttl` | `uint32_t` | Original TTL from the network, in seconds. Goodbye records (TTL=0 on the wire) are stored as `wire_ttl == 1` per the RFC 6762 §10.1 one-second grace period. |
| `ttl_remaining` | `std::chrono::nanoseconds` | Time remaining until record expiry, computed from `wire_ttl` and the time elapsed since insertion. May be negative for records that have already expired but not yet been evicted by `erase_expired()`. |

**Note:** `cache_entry` is a pure value type with no internal synchronization. Values returned by `record_cache::find()`, `snapshot()`, and `erase_expired()` are snapshots computed at the moment the call returns.

## Accessing the Record

Use `std::visit` to access the concrete record type:

```cpp
mdnspp::cache_entry entry = /* from find() or snapshot() */;

std::visit([&entry](const auto &r)
{
    std::cout << "name=" << r.name
              << " wire_ttl=" << entry.wire_ttl << "s"
              << " remaining="
              << std::chrono::duration_cast<std::chrono::seconds>(entry.ttl_remaining).count()
              << "s\n";
}, entry.record);
```

The variant member types and their discriminating fields:

| Variant Type | Key Fields |
|--------------|------------|
| `record_a` | `name`, `address_string` (IPv4 as string) |
| `record_aaaa` | `name`, `address_string` (IPv6 as string) |
| `record_ptr` | `name`, `ptr_name` |
| `record_srv` | `name`, `srv_name`, `port`, `priority`, `weight` |
| `record_txt` | `name`, `entries` (vector of `service_txt`) |

All record types also carry `ttl`, `rclass`, and `cache_flush` fields directly on the variant member (mirroring the wire format). The `cache_entry::wire_ttl` and `cache_entry::ttl_remaining` fields are the authoritative TTL values as tracked by the cache.

## Usage Example

```cpp
#include <mdnspp/record_cache.h>

#include <iostream>

void print_cache(const mdnspp::record_cache<> &cache)
{
    auto entries = cache.snapshot();
    for (const auto &e : entries)
    {
        auto remaining = std::chrono::duration_cast<std::chrono::seconds>(e.ttl_remaining);
        std::visit([&](const auto &r)
        {
            std::cout << r.name
                      << " ttl=" << e.wire_ttl << "s"
                      << " remaining=" << remaining.count() << "s"
                      << " origin=" << e.origin
                      << (e.cache_flush ? " [flush]" : "")
                      << "\n";
        }, e.record);
    }
}
```

## See Also

- [record_cache](record_cache.md) -- the cache that produces `cache_entry` values
- [cache_options](cache_options.md) -- `on_expired` and `on_cache_flush` callbacks receive `cache_entry` values
