# goodbye_grace in cache_options

| | |
|---|---|
| **Type** | `std::chrono::seconds` |
| **Default** | `1` (1 second) |
| **RFC** | RFC 6762 §10.1 |
| **One-liner** | Grace period for goodbye records (TTL=0) before they are evicted from the cache. |

## What

When the library receives an mDNS record with TTL set to 0 (a goodbye announcement, RFC 6762 §11.3), it does not evict the record immediately. Instead, it retains the record for `goodbye_grace` seconds so that the application has time to observe the goodbye before the entry disappears from the cache.

RFC 6762 §10.1 specifies that goodbye records should be retained for 1 second. After the grace period, the record is evicted and `on_expired` fires with the expired entry.

## Why

Increase `goodbye_grace` when:

- The application processes cache events on a delayed or batched schedule and needs more time to consume goodbye notifications before the record is removed.
- The executor tick rate is slow and a 1-second grace window may be too tight.

Reduce `goodbye_grace` when:

- Very rapid service lifecycle (sub-second goodbye-to-removal) is required for testing purposes.
- Cache memory is constrained and holding TTL=0 records even briefly is undesirable.

## Danger

- **Reducing below 1 second may evict goodbye records before the application has a chance to process them.** If `on_expired` processing is delayed (e.g., deferred handlers), the callback may fire with a record that `goodbye_grace` has already evicted.
- **Increasing causes stale records to linger longer in the cache after a goodbye announcement.** During the grace window, the record is still technically in the cache with TTL=0; code that queries the cache may observe the entry before eviction.
- Setting `goodbye_grace` to zero means goodbye records are evicted immediately on receipt, which may cause race conditions in applications that check the cache after receiving the `on_expired` notification.
