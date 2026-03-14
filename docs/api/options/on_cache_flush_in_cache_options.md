# on_cache_flush in cache_options

| | |
|---|---|
| **Type** | `void(const cache_entry&, std::vector<cache_entry>)` |
| **Default** | `{}` (empty — no notification) |
| **One-liner** | Fired when a DNS Cache Flush (CF) bit triggers eviction of records that conflict with a newly received authoritative record. |

## What

`on_cache_flush` is a `move_only_function` callback invoked when the library processes a record with the DNS Cache Flush bit set (RFC 6762 §11.3). When a flush-flagged record is received, any existing cached records of the same name and type from a different source are evicted. This callback delivers:

- The newly received authoritative record (first argument, `const cache_entry&`)
- The vector of evicted records that were displaced by it (second argument, `std::vector<cache_entry>`)

Cache flushes occur when a host re-announces its address or other authoritative records after an address change, ensuring stale records are purged from caches network-wide.

## Why

Use `on_cache_flush` when:

- The application needs to know when a host's address or records have changed (not just expired).
- Tracking which records were replaced to update UI state or routing tables.
- Diagnosing unexpected cache evictions caused by misbehaving hosts.

## Danger

- **Blocking inside the callback is unsafe.** The callback runs on the executor thread.
- **Throwing inside the callback propagates the exception through the executor.** Wrap callback bodies in `try/catch`.
- The evicted records vector may be empty if the incoming flush record was genuinely new and no existing records were displaced.
- A malicious or malfunctioning host can send flush-flagged records to force cache evictions across the network. `on_cache_flush` will fire for each such event regardless of the record's legitimacy.
