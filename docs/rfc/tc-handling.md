# TC Bit and Multi-Packet Known-Answer Lists

When a querier's known-answer list is too large to fit in a single DNS packet,
it sets the TC (Truncated) bit in the header and sends the overflow records in
one or more continuation packets. RFC 6762 section 5.4 requires the responder
to detect the TC bit and wait for all continuation packets before checking
known-answer suppression and generating a response. Without this wait, the
responder would respond with records the querier already holds.

**RFC Reference:** RFC 6762 section 5.4 (TC bit on queries), section 7.2
(multi-packet known-answer lists)

## Example

TC bit handling is automatic in `service_server`. The 400–500 ms accumulation
window is configurable via `mdns_options`:

```cpp
#include <mdnspp/defaults.h>
#include <mdnspp/service_info.h>

int main()
{
    mdnspp::context ctx;

    mdnspp::service_info info{
        .service_name = "MyApp._http._tcp.local.",
        .service_type = "_http._tcp.local.",
        .hostname     = "myhost.local.",
        .port         = 8080,
        .address_ipv4 = "192.168.1.42",
    };

    // TC wait defaults to [400 ms, 500 ms] — RFC-compliant, no tuning needed
    mdnspp::service_server srv{ctx, std::move(info)};

    srv.async_start(
        [](std::error_code ec) { /* ready */ },
        [&ctx](std::error_code) { ctx.stop(); });

    ctx.run();
}
```

To tighten or extend the accumulation window:

```cpp
#include <mdnspp/mdns_options.h>

mdnspp::mdns_options opts{
    .tc_wait_min = std::chrono::milliseconds{350},
    .tc_wait_max = std::chrono::milliseconds{450},
};
mdnspp::service_server srv{ctx, std::move(info), {}, opts};
```

See also: [examples/service_server/](../../examples/service_server/)

## Compliance Status

| Status | Aspect | Notes |
|--------|--------|-------|
| Implemented | TC bit detection on incoming queries | Checked in `service_server` receive path |
| Implemented | 400–500 ms configurable wait | `tc_wait_min` / `tc_wait_max` in `mdns_options` |
| Implemented | Known-answer accumulation from same source IP | `tc_accumulator` keyed by source endpoint |
| Not implemented | Client-side TC bit sending | Querier does not split large known-answer lists across packets (PROTO-04) |

## In-Depth

### TC accumulator

When a query arrives with the TC bit set, the server calls
`detail::tc_accumulator::accumulate()` with the source endpoint and the
records from the Answer section of that packet. The accumulator stores the
records in a `std::unordered_map` keyed by `endpoint` (address + port).

The timer is armed once at first-packet arrival (`inserted_at = Clock::now()`).
Continuation packets from the same source — identified by their lack of a
Questions section — are appended to the existing record list without resetting
the timer. This is the "arm-once" invariant: RFC 6762 states the wait begins at
the first truncated query packet, not at the last continuation.

### Ready check and timeout

After arming the timer, the server schedules a callback at a random duration
uniformly sampled from `[tc_wait_min, tc_wait_max]`. When the callback fires,
it calls `tc_accumulator::take_if_ready()` with `time_point::max()` as the
`now` argument. Passing `max` guarantees the deadline check passes immediately
when the timer fires, decoupling the logical accumulation wait from the
real-time clock in tests.

`take_if_ready` returns the accumulated record vector and removes the entry. The
server then proceeds with the complete known-answer set as if the entire list
had arrived in a single packet.

### Per-source isolation

Each source IP is accumulated independently. A second querier from a different
IP address that also sends a TC query gets its own accumulation entry and its
own timer. The two accumulation windows do not interfere.

### Implementation references

- `mdnspp/detail/tc_accumulator.h` — `tc_accumulator<Clock>`, `accumulate`, `take_if_ready`
- `mdnspp/mdns_options.h` — `tc_wait_min`, `tc_wait_max`

## See Also

- [mdns-options](../mdns-options.md) — full `mdns_options` struct reference
- [service_server API](../api/service_server.md)
- [Known-Answer Suppression](known-answer-suppression.md) — suppression applied after TC accumulation
