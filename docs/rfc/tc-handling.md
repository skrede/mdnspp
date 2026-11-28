# TC Bit and Multi-Packet Known-Answer Lists

When a querier's known-answer list is too large to fit in a single DNS packet,
it sets the TC (Truncated) bit in the header and sends the overflow records in
one or more continuation packets. RFC 6762 section 6 requires the responder
to detect the TC bit and delay its response by 400-500 ms to wait for all
continuation packets before checking known-answer suppression and generating
a response. Without this wait, the responder would respond with records the
querier already holds.

**RFC Reference:** RFC 6762 section 6 (responder wait on TC queries),
section 7.2 (multi-packet known-answer lists), section 18.5 (TC bit
semantics)

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
| Implemented | Known-answer accumulation per source, with per-source deadlines | `tc_accumulator` keyed by source endpoint; one timer armed for the earliest deadline drains all expired sources |
| Implemented | Final-continuation merge (§7.2) | A compliant querier's final continuation (TC clear, qdcount=0) is merged into the pending TC state before the suppression decision |
| Implemented | Querier-side TC splitting (§7.2) | Outgoing queries exceeding `max_query_payload` are split: each packet but the last sets TC; continuation packets carry no questions (qdcount=0) |

## In-Depth

### TC accumulator

When a query arrives with the TC bit set, the server calls
`detail::tc_accumulator::accumulate()` with the source endpoint and the
records from the Answer section of that packet. The accumulator stores the
records in a `std::unordered_map` keyed by `endpoint` (address + port), each
entry carrying its own drain deadline (`Clock::now()` plus a random duration
uniformly sampled from `[tc_wait_min, tc_wait_max]`).

The deadline is fixed at first-packet arrival. Continuation packets from the
same source are appended to the existing record list without resetting the
deadline. This is the "arm-once" invariant: RFC 6762 states the wait begins
at the first truncated query packet, not at the last continuation. A
compliant querier's final continuation packet -- TC bit clear and no
questions (qdcount=0) -- is also merged into the pending state, so the
suppression decision sees the complete known-answer set.

### Per-source deadlines, single timer

Each source endpoint is accumulated independently with its own deadline, but
the server arms a single timer for the earliest pending deadline
(`tc_accumulator::next_deadline()`). When the timer fires,
`tc_accumulator::take_expired(now)` removes and returns the merged record
sets of all sources whose deadline has passed, and the timer is re-armed for
the next earliest deadline. A second querier whose TC query arrives while
another source's window is pending therefore never cancels or extends the
first source's wait.

The accumulator bounds memory growth from spoofed source endpoints: at most
`tc_accumulator::max_pending_sources` (64) sources are pending at once; when
full, the entry with the earliest deadline is dropped to admit the new
source.

### Implementation references

- `mdnspp/detail/tc_accumulator.h` — `tc_accumulator<Clock>`, `accumulate`, `next_deadline`, `take_expired`
- `mdnspp/mdns_options.h` — `tc_wait_min`, `tc_wait_max`, `max_query_payload`, `tc_continuation_delay`

## See Also

- [mdns-options](../mdns-options.md) — full `mdns_options` struct reference
- [service_server API](../api/service_server.md)
- [Known-Answer Suppression](known-answer-suppression.md) — suppression applied after TC accumulation
