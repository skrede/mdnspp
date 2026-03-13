# cache_options

Configuration struct for `record_cache` expiry, cache-flush callbacks, and goodbye grace period.

## Header

```cpp
#include <mdnspp/cache_options.h>
```

## Fields

```cpp
struct cache_options {
    detail::move_only_function<void(std::vector<cache_entry>)>                       on_expired{};
    detail::move_only_function<void(const cache_entry &, std::vector<cache_entry>)>  on_cache_flush{};
    std::chrono::seconds                                                              goodbye_grace{1};
};
```

| Field | Type | Default | RFC Section | Description |
|-------|------|---------|-------------|-------------|
| `on_expired` | `move_only_function<void(std::vector<cache_entry>)>` | `{}` | RFC 6762 §5.2 | Fires after `erase_expired()` removes one or more entries. Receives the expired entries. Called with the cache lock released. If not set, expired entries are silently discarded. |
| `on_cache_flush` | `move_only_function<void(const cache_entry &, std::vector<cache_entry>)>` | `{}` | RFC 6762 §10.2 | Fires when a cache-flush record schedules other records for rapid expiry. The first argument is the authoritative record (with `cache_flush == true`) from the announcing host; the second is the list of same-name/same-type records from other origins that will be flushed. Called with the cache lock temporarily released. If not set, cache-flush events are silently handled (the records are still flushed). |
| `goodbye_grace` | `std::chrono::seconds` | `1s` | RFC 6762 §10.1 | Grace period for goodbye records (TTL=0) before they are evicted from the cache. When a record is received with TTL=0 it is retained for this duration so that the application can observe the goodbye before eviction. |

**Note:** All callbacks are optional. If not set, the cache still correctly implements RFC 6762 TTL expiry, cache-flush semantics, and goodbye handling -- the callbacks are pure observation hooks.

All fields are move-only (`detail::move_only_function`). Use `std::move` when passing a named `cache_options` to the `record_cache` constructor.

Use C++20 designated initializers for readability:

```cpp
mdnspp::cache_options opts{
    .on_expired = [](std::vector<mdnspp::cache_entry> expired)
    {
        for (const auto &e : expired)
            std::visit([](const auto &r) { std::cout << "expired: " << r.name << "\n"; }, e.record);
    },
};
```

## Usage Example

```cpp
#include <mdnspp/record_cache.h>

#include <iostream>

int main()
{
    mdnspp::cache_options opts{
        .on_expired = [](std::vector<mdnspp::cache_entry> expired)
        {
            for (const auto &e : expired)
            {
                std::visit([&e](const auto &r)
                {
                    std::cout << "TTL expired: " << r.name
                              << " (was " << e.wire_ttl << "s)\n";
                }, e.record);
            }
        },
        .on_cache_flush = [](const mdnspp::cache_entry &auth,
                             std::vector<mdnspp::cache_entry> flushed)
        {
            std::visit([](const auto &r) {
                std::cout << "cache flush from " << r.name << "\n";
            }, auth.record);
            std::cout << "  flushing " << flushed.size() << " stale record(s)\n";
        },
        .goodbye_grace = std::chrono::seconds{2},
    };

    mdnspp::record_cache<> cache{std::move(opts)};

    // ... insert and use the cache ...
}
```

## See Also

- [record_cache](record_cache.md) -- the cache that consumes these options
- [cache_entry](cache_entry.md) -- the value type passed to both callbacks
- [record-cache](../record-cache.md) -- conceptual guide to cache semantics
