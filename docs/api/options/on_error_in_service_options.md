# on_error in service_options

| | |
|---|---|
| **Type** | `move_only_function<void(std::error_code ec, std::string_view context)>` |
| **Default** | `{}` (empty — errors are silently ignored) |
| **One-liner** | Invoked on fire-and-forget send failures and address encoding errors. |

## What

`on_error` receives errors from operations that have no completion handler of their own: probe, announcement, response, and goodbye sends, fatal receive-loop errors, and invalid `service_info` address fields detected when building responses.

Signature:

```cpp
void on_error(
    std::error_code  ec,       // the failure
    std::string_view context   // the failure site, e.g. "probe send",
                               // "announcement send", "response send",
                               // "goodbye send", "receive",
                               // "invalid IPv4 address: <addr>"
);
```

The same `error_handler` shape appears on the consumer side as `monitor_options::on_error`, `query_options::on_error`, and `observer_options::on_error`.

## Why

Set `on_error` in any deployment where a silently mute server is unacceptable. A server whose sends consistently fail (interface down, firewall, invalid address in `service_info`) continues running — probing and timers proceed — but announces nothing; `on_error` is the only place this surfaces.

## Danger

- **Without a handler these errors are invisible.** There is no logging fallback; the send result is discarded.
- **The callback runs on the executor thread.** Do not block inside it.
- **Transient send failures are normal** during interface reconfiguration (DHCP renewal, Wi-Fi roam); treat isolated errors as advisory and patterns of repetition as actionable.
