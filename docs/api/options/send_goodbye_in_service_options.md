# send_goodbye in service_options

| | |
|---|---|
| **Type** | `bool` |
| **Default** | `true` |
| **One-liner** | Whether to send a goodbye packet (TTL=0) for all records when the service shuts down. |

## What

When the service server is stopped gracefully, it can send a goodbye announcement by re-advertising all its records with TTL set to 0. RFC 6762 §11.3 defines this as an optional but strongly recommended courtesy: it allows queriers to immediately evict the record from their caches rather than waiting for the original TTL to expire.

With `send_goodbye = true` (the default), the library sends a TTL=0 multicast packet on graceful shutdown. With `false`, the service simply stops and remote caches retain the record until the original TTL expires.

## Why

Set `send_goodbye = false` when:

- The service crashes or is killed non-gracefully anyway and consistency with those paths is preferred.
- Sending a goodbye packet would reveal shutdown timing to observers (rare security concern).
- The service will restart immediately and there is no benefit in clearing caches.

Keep `send_goodbye = true` (the default) in all other cases. It reduces the time remote caches take to converge after a service leaves the network.

## Danger

- **Disabling goodbye means caches retain stale records for the full original TTL** (up to 4500 seconds by default). During this window, queriers attempting to connect to the service will see a dead record.
- The goodbye packet is sent only on graceful shutdown paths. A process crash bypasses this entirely regardless of setting.
- On networks where multicast is unreliable, even `send_goodbye = true` provides no guarantee that all listeners receive the goodbye.
