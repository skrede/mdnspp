# probe_defer_delay in service_options

| | |
|---|---|
| **Type** | `std::chrono::milliseconds` |
| **Default** | `1000` (1 second) |
| **RFC** | RFC 6762 §8.2 |
| **One-liner** | Delay before re-probing after losing a simultaneous-probe tiebreak. |

## What

When the tiebreaking comparison defined in RFC 6762 §8.2 indicates that the remote probe wins, the local node must defer and restart its probe sequence. `probe_defer_delay` is the pause between losing the tiebreak and beginning the new probe sequence.

The `on_conflict` callback is invoked with `conflict_type::tiebreak_deferred` before the defer delay begins, giving the application an opportunity to rename the service or abort.

RFC 6762 §8.2 specifies approximately 1 second as the recommended deferral duration. The default of 1000 ms matches the RFC.

## Why

Reduce `probe_defer_delay` when:

- Fast service startup is critical and the application operates in a controlled environment where simultaneous probe storms are unlikely.
- Rename-and-retry latency must be minimised.

Increase `probe_defer_delay` when:

- Multiple nodes start simultaneously and more aggressive desynchronisation of their retry waves is needed.
- Re-probe storms after bulk simultaneous startup must be dampened.

## Danger

- **Reducing to zero may cause a rapid storm of re-probes** if multiple nodes start simultaneously. Each node immediately restarts its probe sequence after losing a tiebreak, generating another round of simultaneous probes and potential repeat deferrals.
- **Increasing delays service startup.** With `probe_defer_delay = 5000 ms` and multiple tiebreak rounds, it may take tens of seconds for a service to successfully probe in a congested environment.
- Very short `probe_defer_delay` combined with many simultaneous starters can lead to oscillating probe/defer cycles that delay all services significantly.
