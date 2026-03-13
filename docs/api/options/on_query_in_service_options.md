# on_query in service_options

| | |
|---|---|
| **Type** | `void(const endpoint& sender, dns_type type, response_mode mode)` |
| **Default** | `{}` (empty — no notification) |
| **One-liner** | Fired each time the service receives an incoming query that matches its records. |

## What

`on_query` is a `move_only_function` callback invoked by the service server each time it receives and is about to process an mDNS query targeting one of its registered records.

Signature:

```cpp
void on_query(
    const endpoint& sender,  // source address and port of the querying host
    dns_type        type,    // record type queried (PTR, SRV, TXT, A, AAAA, ANY, …)
    response_mode   mode     // multicast, unicast, or unicast_legacy
);
```

`response_mode` reflects how the service will respond:

- `response_mode::multicast` — standard multicast response
- `response_mode::unicast` — unicast response requested via QU bit
- `response_mode::unicast_legacy` — legacy unicast query (source port ≠ 5353); TTLs capped per `mdns_options::legacy_unicast_ttl`

The callback is informational. It cannot suppress the response or modify it.

## Why

Use `on_query` for:

- **Diagnostics and telemetry** — count how often the service is queried and by whom.
- **Debugging resolution issues** — log unexpected unicast or legacy-mode queries.
- **Activity monitoring** — detect when the service is actively being used by clients.

## Danger

- **Blocking inside the callback is unsafe.** The callback runs on the executor thread; long-running work blocks mDNS processing.
- **Throwing inside the callback propagates the exception through the executor.** Wrap callback bodies in `try/catch`.
- The callback fires for each matching record type in a multi-question query; a single incoming packet may trigger multiple invocations.
