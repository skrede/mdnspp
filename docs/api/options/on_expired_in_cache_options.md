# on_expired in cache_options

| | |
|---|---|
| **Type** | `void(std::vector<cache_entry>)` |
| **Default** | `{}` (empty — no notification) |
| **One-liner** | Fired when one or more cache entries expire naturally (TTL reaches zero and goodbye grace period passes). |

## What

`on_expired` is a `move_only_function` callback invoked by the record cache when entries are evicted due to TTL expiry. The callback receives a `std::vector<cache_entry>` containing all records evicted in the same eviction sweep.

Natural expiry differs from goodbye eviction: a record expires naturally when its TTL counts down to zero without a goodbye packet being received. Records received with TTL=0 (goodbye records) are held for `goodbye_grace` before eviction and delivered via `on_expired` after the grace period.

The callback is invoked from the executor thread.

## Why

Use `on_expired` when:

- The application needs to react when a service disappears without an explicit goodbye (e.g., a crashed host).
- Tracking cache size or eviction rates for diagnostics.
- Updating application state (e.g., removing a service from a UI) when its records expire.

## Danger

- **Blocking inside the callback is unsafe.** The callback runs on the executor thread; long-running operations block all mDNS processing.
- **Throwing inside the callback propagates the exception through the executor.** Wrap callback bodies in `try/catch`.
- The callback may be called with a batch of multiple entries from a single eviction sweep; the vector may contain records of different types from different hosts.
- Expiry callbacks for goodbye records fire after the `goodbye_grace` period, not immediately on receipt of the goodbye packet. Do not depend on immediate delivery.
