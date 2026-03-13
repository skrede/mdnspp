# on_conflict in service_options

| | |
|---|---|
| **Type** | `bool(const std::string& conflicting_name, std::string& new_name, unsigned attempt, conflict_type type)` |
| **Default** | `{}` (empty — library uses built-in renaming) |
| **One-liner** | Invoked when a name conflict is detected; returns `true` to accept the proposed `new_name`, `false` to abort. |

## What

`on_conflict` is a `move_only_function` callback fired by the service server whenever a naming conflict is detected during probing or after announcement.

Signature:

```cpp
bool on_conflict(
    const std::string& conflicting_name,  // the name that was contested
    std::string&       new_name,          // proposed replacement name (modifiable)
    unsigned           attempt,           // how many conflicts have occurred so far (1-based)
    conflict_type      type               // name_conflict or tiebreak_deferred
);
```

`conflict_type` has two values:

- `conflict_type::name_conflict` — a simultaneous probe from another host claimed the same name
- `conflict_type::tiebreak_deferred` — the local probe lost the RFC 6762 §8.2 tiebreak comparison; the service will re-probe after `probe_defer_delay`

The callback may modify `new_name` to supply an alternate service name. Return `true` to accept the name in `new_name` and continue probing under that name. Return `false` to abort service registration.

When `on_conflict` is not set, the library's built-in strategy appends `" (2)"`, `" (3)"`, … to the original name on each successive attempt.

## Why

Override `on_conflict` when:

- The application wants deterministic renaming (e.g., appending a device serial number instead of a counter).
- The application wants to log conflicts or alert an operator.
- The application wants to abort registration on conflict rather than auto-renaming (return `false`).
- The `conflict_type` matters — the application may accept tiebreak deferrals silently but alert on true name conflicts.

## Danger

- **Blocking inside the callback is unsafe.** The callback runs on the executor thread. Long-running operations (network calls, file I/O, mutex acquisition) block all mDNS processing for the duration.
- **Throwing inside the callback propagates the exception through the executor.** Catch all exceptions within the callback body.
- **Returning `false` permanently stops the service.** The server does not attempt further probing; `async_start` will not complete with a success code. Call `async_start` again if retry is needed.
- **Infinite conflict loops:** If `new_name` is always contested, the callback will be invoked repeatedly. Use `attempt` to cap retries and return `false` after a threshold.
