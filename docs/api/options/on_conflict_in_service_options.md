# on_conflict in service_options

| | |
|---|---|
| **Type** | `move_only_function<std::optional<std::string>(std::string_view conflicting_name, uint32_t attempt, conflict_type type)>` |
| **Default** | `{}` (empty — a conflict permanently fails startup) |
| **RFC** | RFC 6762 §8.1, §8.2.1, §9 |
| **One-liner** | Invoked when a name conflict is detected; returns the replacement service instance name, or `std::nullopt` to give up. |

## What

`on_conflict` is fired by the service server whenever a naming conflict is detected — during probing (§8.1), when a simultaneous-probe tiebreak is lost (§8.2.1), or while live (§9 post-probe conflict detection).

Signature:

```cpp
std::optional<std::string> on_conflict(
    std::string_view conflicting_name,  // the name that was contested
    uint32_t         attempt,           // conflicts so far for this start (0-based)
    conflict_type    type               // name_conflict or tiebreak_deferred
);
```

`conflict_type` has two values:

- `conflict_type::name_conflict` — another responder asserted different data for the proposed (or live) unique name. Return a replacement service instance name to re-probe under that name, or `std::nullopt` to give up.
- `conflict_type::tiebreak_deferred` — the local probe lost the RFC 6762 §8.2.1 tiebreak comparison against a simultaneous prober. The return value is ignored; the server re-probes the *same* name after `probe_defer_delay`. The callback fires for observability only.

When `on_conflict` is not set (or returns `std::nullopt`) for a `name_conflict`, the server tears down: `on_ready` fires with `mdns_error::probe_conflict`, the teardown runs, and `on_done` fires with `std::error_code{}`. There is no built-in automatic renaming.

Re-probing after a rename is rate-limited per §8.1: after 15 conflicts within 10 seconds, every probe attempt waits at least 5 seconds.

## Why

Set `on_conflict` when:

- The service should rename itself and stay up rather than fail — e.g. append a counter or a device serial number: `"MyApp (" + std::to_string(attempt + 2) + ")._http._tcp.local."`.
- Conflicts should be logged or surfaced to an operator.
- The `conflict_type` matters — the application may ignore tiebreak deferrals but alert on true name conflicts.

## Danger

- **Blocking inside the callback is unsafe.** The callback runs on the executor thread. Long-running operations (network calls, file I/O, mutex acquisition) block all mDNS processing for the duration.
- **Returning `std::nullopt` permanently stops the server.** `on_ready` completes with `mdns_error::probe_conflict` and `on_done` fires after teardown; the instance cannot be restarted (`async_start` is one-shot) — construct a new server to retry.
- **Infinite conflict loops:** if every returned name is also contested, the callback is invoked repeatedly (throttled by the §8.1 rate limiter). Use `attempt` to cap retries and return `std::nullopt` after a threshold.
- **The returned name must be a full service instance name** (e.g. `"MyApp-2._http._tcp.local."`), consistent with `service_info::service_type`. An unencodable name (label > 63 bytes, name > 255 bytes) fails startup with `std::errc::invalid_argument`.
