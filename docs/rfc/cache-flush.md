# Cache-Flush Bit

The cache-flush bit is the top bit of the rrclass field in every DNS resource
record. When set, it signals that the sender is the authoritative source for
this name and type and that all other cached records of the same name+type from
different sources should be evicted. A 1-second grace period prevents premature
eviction during simultaneous announcements from multiple hosts that are not yet
aware of each other.

**RFC Reference:** RFC 6762 section 10.2

## Example

Cache-flush handling is automatic in `record_cache`. To observe flush events,
register an `on_cache_flush` callback in `cache_options`:

```cpp
#include <mdnspp/record_cache.h>
#include <mdnspp/cache_options.h>

#include <iostream>

int main()
{
    mdnspp::cache_options opts;
    opts.on_cache_flush = [](const mdnspp::cache_entry &authoritative,
                              std::vector<mdnspp::cache_entry> affected)
    {
        std::cout << "cache flush: " << affected.size()
                  << " stale record(s) marked for eviction\n";
        std::cout << "  authoritative from: " << authoritative.origin.address << "\n";
        for (const auto &e : affected)
            std::cout << "  evicting from: " << e.origin.address << "\n";
    };

    mdnspp::record_cache cache{std::move(opts)};

    // Records inserted with cache_flush = true will trigger the callback above
    // when they collide with existing records from different origins.
}
```

See also: [examples/record_cache/](../../examples/record_cache/)

## Compliance Status

| Status | Aspect | Notes |
|--------|--------|-------|
| Implemented | Cache-flush bit extraction from wire format | Top bit of rrclass; actual class preserved in lower 15 bits |
| Implemented | Propagation through all record types to cache | All five record types carry `cache_flush` field |
| Implemented | 1-second grace period before flushing stale records | `flush_deadline = now + 1s` on conflicting entries |
| Implemented | `on_cache_flush` callback notification | Fired immediately when flush deadline is assigned |
| Related | Goodbye (TTL=0) handling in cache (section 10.1) | Also implemented; see [goodbye.md](goodbye.md) |

## In-Depth

### Bit extraction

On the wire, DNS rrclass is a 16-bit field. The top bit is repurposed by
mDNS as the cache-flush indicator. When parsing, mdnspp extracts the class
value from bits 14–0 and stores the cache-flush flag separately as a `bool`
field on every record type (`record_a`, `record_aaaa`, `record_ptr`,
`record_srv`, `record_txt`).

### Flush semantics

When `record_cache::insert()` receives a record with `cache_flush = true`, it
calls `apply_cache_flush` after inserting or updating the record. That function
iterates all existing entries under the same `(name, type)` key and:

1. **Same origin** — the authoritative entry is identified for use in the
   callback but is not marked for eviction.
2. **Different origin** — each entry gets a `flush_deadline` of
   `now + std::chrono::seconds(1)`. If an entry already has a closer deadline
   it is left unchanged.

The `on_cache_flush` callback is fired immediately (while `apply_cache_flush`
temporarily releases the internal lock) with the authoritative entry and the
list of affected entries. This gives callers an early notification before the
actual eviction happens.

### Eviction timing

Actual eviction happens lazily during the next `erase_expired()` call.
`is_expired` returns `true` for any entry whose `flush_deadline` is in the
past, independently of its TTL. The 1-second grace period means a record
cannot be evicted before `now + 1s` from the flush event, which gives
simultaneous announcers time to complete their own announcements before
any host starts discarding records.

### Re-announcement path

The flush logic runs on both the new-insert path and the identity-dedup path
(`record_identity_equal` match). This means that when an authoritative host
re-announces a record it already owns, it still triggers a flush of stale
copies from other origins that may have appeared in the interim.

### Implementation references

- `mdnspp/record_cache.h` — `record_cache<Clock>`, `insert`, `apply_cache_flush`,
  `erase_expired`, `is_expired`
- `mdnspp/cache_options.h` — `cache_options::on_cache_flush` callback signature
- `mdnspp/cache_entry.h` — `cache_entry` struct returned to callbacks

## See Also

- [record-cache](../record-cache.md) — full `record_cache` usage guide
- [Goodbye Packets](goodbye.md) — TTL=0 eviction (section 10.1)
- [record_cache API](../api/record_cache.md)
