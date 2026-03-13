# on_tc_continuation in service_options

| | |
|---|---|
| **Type** | `void(const endpoint& sender, std::size_t continuation_count)` |
| **Default** | `{}` (empty — no notification) |
| **One-liner** | Fired when a TC (truncated) continuation batch is processed; reports the sender and the number of accumulated continuation packets. |

## What

`on_tc_continuation` is a `move_only_function` callback invoked after the service server finishes accumulating and processing a truncated-continuation (TC) query sequence.

Signature:

```cpp
void on_tc_continuation(
    const endpoint& sender,              // source of the TC query chain
    std::size_t     continuation_count   // number of continuation packets received
);
```

When an mDNS query arrives with the TC (truncation) bit set (RFC 6762 §6), the service waits for follow-up packets carrying additional known-answer records. After the wait window defined by `mdns_options::tc_wait_min`/`tc_wait_max` expires, this callback fires with the total count of continuation packets that arrived from `sender`.

The callback is informational. It fires after the TC batch has been processed; it cannot modify or delay the response.

## Why

Use `on_tc_continuation` for:

- **Diagnostics** — detect clients sending unusually large known-answer lists.
- **Capacity planning** — measure how frequently TC fragmentation occurs on the network.
- **Debugging known-answer suppression** — verify that TC accumulation is working when expected suppressions are not occurring.

## Danger

- **Blocking inside the callback is unsafe.** The callback runs on the executor thread.
- **Throwing inside the callback propagates the exception through the executor.** Wrap callback bodies in `try/catch`.
- `continuation_count` may be zero if the initial TC packet arrived but no continuation packets followed within the wait window; this represents a truncated query that was never completed by the sender.
