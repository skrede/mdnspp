# Record Cache

`record_cache` is a standalone, policy-free type that stores mDNS records with
TTL tracking. It has no dependency on sockets, timers, or any `basic_*` type
from mdnspp -- it holds records and lets you query or expire them at any time.

`record_cache` is not included from `<mdnspp/defaults.h>`. Include it directly:

```cpp
#include <mdnspp/record_cache.h>
```

## Primer

### Quick start

```cpp
#include <mdnspp/record_cache.h>
#include <mdnspp/cache_options.h>

mdnspp::record_cache<> cache; // uses std::chrono::steady_clock

// Insert a record received from the network
mdnspp::endpoint origin{"192.168.1.1", 5353};
cache.insert(some_record_variant, origin);

// Look up all SRV records for a known instance
auto entries = cache.find("MyServer._http._tcp.local.", mdnspp::dns_type::srv);
for (const auto &e : entries)
    std::cout << "TTL remaining: " << e.ttl_remaining.count() / 1'000'000'000 << "s\n";

// Full snapshot of every record in the cache
auto all = cache.snapshot();

// Evict all expired records (call periodically or after advancing test_clock)
auto expired = cache.erase_expired();
```

### Observer wiring (promiscuous record collection)

A common pattern is to wire `record_cache` to an `observer` to collect every
record seen on the network, without caring about any particular service type:

```cpp
#include <mdnspp/defaults.h>
#include <mdnspp/record_cache.h>
#include <mdnspp/observer_options.h>

mdnspp::context ctx;
mdnspp::record_cache<> cache;

mdnspp::observer obs{ctx,
    mdnspp::observer_options{
        .on_record = [&cache](const mdnspp::endpoint &sender,
                               const mdnspp::mdns_record_variant &rec)
        {
            cache.insert(rec, sender);
        }
    }
};

obs.async_observe([&ctx](std::error_code) { ctx.stop(); });
ctx.run();

// After ctx.run() returns, inspect the cache
auto snap = cache.snapshot();
```

This wiring is entirely manual -- `record_cache` does not know about `observer`
and `observer` does not know about `record_cache`. Any code that receives
`mdns_record_variant` values can feed them in.

## In-Depth

### Template parameter

```cpp
template <typename Clock = std::chrono::steady_clock>
class record_cache;
```

The `Clock` parameter controls how insertion time and expiry are computed.
The default `std::chrono::steady_clock` is correct for production use.

Substitute `mdnspp::testing::test_clock` in unit tests to advance time
deterministically without real sleeps:

```cpp
#include <mdnspp/testing/test_clock.h>
mdnspp::record_cache<mdnspp::testing::test_clock> cache;
// Advance time without sleeping:
mdnspp::testing::test_clock::advance(std::chrono::seconds{30});
auto expired = cache.erase_expired();
```

### cache_options

Pass `cache_options` at construction to receive eviction notifications:

```cpp
mdnspp::cache_options opts{
    .on_expired = [](std::vector<mdnspp::cache_entry> expired) {
        for (const auto &e : expired)
            std::cout << "expired\n";
    },
    .on_cache_flush = [](const mdnspp::cache_entry &authoritative,
                          std::vector<mdnspp::cache_entry> affected) {
        // A cache-flush record was received; `affected` entries from other
        // origins for the same name+type have been scheduled for eviction.
    },
};

mdnspp::record_cache<> cache{std::move(opts)};
```

`on_expired` fires inside `erase_expired()` after the expired entries have
been removed from the internal storage. Callbacks are made with the lock
released.

`on_cache_flush` fires when a record with the cache-flush bit set is inserted
and records from other origins exist for the same name+type. The `affected`
entries are scheduled for eviction after a 1-second grace period per RFC 6762
section 10.2, but have not been removed yet at callback time.

### Insert semantics

`insert(record, origin)` uses record identity (name + type + class + rdata)
for deduplication:

- If an identical record is already cached, its insertion time is refreshed
  (effectively extending the TTL). No duplicate entry is created.
- If the record is new, it is inserted fresh.
- If the record's TTL is 0 (goodbye packet), the effective TTL is set to 1
  second per RFC 6762 section 10.1. The record is retained briefly to allow
  all subscribers to observe the goodbye before it expires naturally.

### Goodbye handling

When TTL=0 is received on the wire, the record is NOT immediately removed.
It is inserted with a 1-second TTL so that the impending loss is observable:
`find()` and `snapshot()` will return the entry with a small `ttl_remaining`.
The next call to `erase_expired()` after the 1-second grace removes it and
fires `on_expired`.

### Cache-flush semantics (RFC 6762 section 10.2)

When a record with the cache-flush bit set arrives, all records of the same
name and type from *other* origins are marked for eviction after a 1-second
grace window. The newly-inserted record from the authoritative sender is
kept. `on_cache_flush` fires immediately with the affected records.

Records from the same origin are considered a TTL refresh (dedup path); the
flush does not apply to them.

### Non-copyable, non-movable

`record_cache` is neither copyable nor movable. Construct it in place and
pass it by pointer or reference.

```cpp
// OK: construct in place
mdnspp::record_cache<> cache;

// OK: pass by reference
void process(mdnspp::record_cache<> &cache) { ... }

// Compile error: copy/move not supported
// mdnspp::record_cache<> cache2 = cache;
```

### Thread safety

`record_cache` uses an internal `std::shared_mutex`. `find()` and `snapshot()`
are safe to call concurrently from multiple reader threads. `insert()` and
`erase_expired()` take an exclusive lock.

Concurrent calls to `insert()` + `erase_expired()` are safe. Callbacks
(`on_expired`, `on_cache_flush`) are called with the internal lock released,
so they may call `find()` or `snapshot()` without deadlock.

## See Also

- [examples/record_cache/](../examples/record_cache/) -- runnable examples
- [API reference: record_cache](api/record_cache.md) -- full type documentation
- [Service Monitor](service-monitor.md) -- higher-level continuous service tracking built on top of record_cache
