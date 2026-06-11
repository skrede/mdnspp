# record_cache

Standalone TTL-aware record cache for mDNS records, usable without sockets or policies.

## Header

```cpp
#include <mdnspp/record_cache.h>
```

`record_cache` is **not** included in `<mdnspp/defaults.h>`. Include the header directly.

## Template Parameters

```cpp
template <typename Clock = std::chrono::steady_clock>
class record_cache;
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `Clock` | `std::chrono::steady_clock` | Clock used to compute TTL expiry and `ttl_remaining`. Substitute `mdnspp::testing::test_clock` in unit tests for deterministic TTL control. |

## Constructors

```cpp
explicit record_cache(cache_options opts = {});
record_cache(cache_options opts, std::error_code &ec);
```

Constructs an empty cache. The optional [`cache_options`](cache_options.md) provides callbacks for record expiry and cache-flush events.

Options are validated at construction: a non-positive `goodbye_grace` is invalid. The throwing constructor throws `std::system_error` with `std::errc::invalid_argument`; the non-throwing overload sets `ec` to `std::errc::invalid_argument` and clamps `goodbye_grace` to one second so the cache remains safe to use.

**Note:** `record_cache` is non-copyable and non-movable. Construct in place. If you need to wire callbacks that capture the cache itself (e.g., for use with `basic_service_monitor`), use the `make_cache_options()` helper pattern: create a `cache_options` whose callbacks capture `this` or a pointer/reference to the cache.

## Methods

### insert

```cpp
void insert(mdns_record_variant rec, endpoint origin);
```

Inserts or updates a record in the cache.

- If a record with the same name, type, DNS class, and rdata already exists, its insertion time and TTL are refreshed (deduplication by identity).
- If `rec.cache_flush == true`, records of the same name/type from different origins that were received more than one second ago are scheduled to expire after `cache_options::goodbye_grace` (default one second, RFC 6762 §10.2), and `cache_options::on_cache_flush` is fired if any were affected. Records received within the last second are exempt (the §10.2 young-record exemption).
- Goodbye records (`rec.ttl == 0`) are retained for `goodbye_grace` then expired (RFC 6762 §10.1).

| Parameter | Type | Description |
|-----------|------|-------------|
| `rec` | `mdns_record_variant` | The record to insert (A, AAAA, PTR, SRV, or TXT). |
| `origin` | `endpoint` | The sender's address and port, used for cache-flush origin tracking. |

**Thread-safety:** Internal `std::shared_mutex` protects all state. Concurrent `insert()` and `find()` calls are safe.

### find

```cpp
auto find(dns_name name, dns_type type) const -> std::vector<cache_entry>;
```

Returns all cached entries matching the given name and DNS type. Returns an empty vector if no matching records are cached.

| Parameter | Type | Description |
|-----------|------|-------------|
| `name` | `dns_name` | The DNS name to look up (e.g. `"_http._tcp.local."`; `dns_name` converts implicitly from string types). Comparison is ASCII case-insensitive. |
| `type` | `dns_type` | The record type (e.g. `dns_type::srv`, `dns_type::a`). |

**Returns:** A vector of [`cache_entry`](cache_entry.md) values with `ttl_remaining` computed at the moment of the call. Does not remove expired entries; call `erase_expired()` separately.

**Thread-safety:** Acquires a shared read lock. Safe to call concurrently with other `find()` or `snapshot()` calls.

### snapshot

```cpp
auto snapshot() const -> std::vector<cache_entry>;
```

Returns a snapshot of all currently-cached records. Each [`cache_entry`](cache_entry.md) has `ttl_remaining` computed at the moment of the call.

Does not evict expired entries. Records whose `ttl_remaining` is negative or zero are included in the snapshot but will be removed by the next `erase_expired()` call.

**Thread-safety:** Acquires a shared read lock. Safe to call concurrently with `find()` and other `snapshot()` calls.

### erase_expired

```cpp
auto erase_expired() -> std::vector<cache_entry>;
```

Removes all expired records from the cache and returns them. An entry is expired when:
- The current time exceeds `inserted_at + wire_ttl` (normal TTL expiry), or
- A cache-flush deadline was set and has elapsed (RFC 6762 §10.2 flush expiry).

If `cache_options::on_expired` is set it fires with the expired entries after the lock is released.

**Returns:** The removed entries (same as what was passed to `on_expired`).

**Thread-safety:** Acquires an exclusive write lock. Safe to call concurrently with any other method; the lock is released before `on_expired` fires.

## Thread-Safety Summary

`record_cache` has internal `std::shared_mutex` synchronization. All methods are safe to call concurrently from multiple threads.

| Operation | Concurrency |
|-----------|-------------|
| `insert()` | Exclusive write lock |
| `find()` | Shared read lock |
| `snapshot()` | Shared read lock |
| `erase_expired()` | Exclusive write lock |

Multiple concurrent readers (`find()`, `snapshot()`) proceed in parallel; writers (`insert()`, `erase_expired()`) are serialized against each other and against readers by the mutex. The `on_expired` and `on_cache_flush` callbacks are invoked with the lock released, so callbacks may call back into the cache.

## Usage Example

```cpp
// Wire an observer to a standalone cache for promiscuous record collection:
// observe for 10 seconds on a worker thread, then introspect the cache.

#include <mdnspp/defaults.h>
#include <mdnspp/record_cache.h>

#include <thread>
#include <iostream>

int main()
{
    mdnspp::context ctx;
    mdnspp::record_cache<> cache;

    mdnspp::observer obs{
        ctx,
        mdnspp::observer_options{
            .on_record = [&cache](const mdnspp::endpoint &sender,
                                  const mdnspp::mdns_record_variant &rec)
            {
                cache.insert(rec, sender);
            }
        }
    };

    std::thread w([&]()
    {
        obs.async_observe();
        ctx.run();
    });
    std::this_thread::sleep_for(std::chrono::seconds(10));
    ctx.stop();
    w.join();

    auto entries = cache.snapshot();
    std::cout << "cached " << entries.size() << " record(s)" << std::endl;
    for(const auto &e : entries)
    {
        std::visit([&e](const auto &r)
        {
            std::cout << "  " << r.name
                      << " ttl=" << e.wire_ttl << "s"
                      << " remaining="
                      << std::chrono::duration_cast<std::chrono::seconds>(e.ttl_remaining).count()
                      << "s" << std::endl;
        }, e.record);
    }
}
```

See also the full [record_cache examples](../../examples/record_cache/) directory.

## See Also

- [record-cache](../record-cache.md) &mdash; conceptual guide: standalone vs wired usage, cache-flush semantics
- [cache_options](cache_options.md) &mdash; expiry and cache-flush callbacks
- [cache_entry](cache_entry.md) -- the value type returned by `find()`, `snapshot()`, `erase_expired()`
- [service_monitor](service_monitor.md) -- uses `record_cache` internally for TTL-aware service tracking
