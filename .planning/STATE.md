---
gsd_state_version: 1.0
milestone: v2.0
milestone_name: Standalone & Ergonomic
status: completed
stopped_at: Completed 11-01-PLAN.md (resolved_service struct, aggregate() with two-pass RFC 6763 correlation; 18 tests pass)
last_updated: "2026-03-04T17:42:01.561Z"
last_activity: 2026-03-04 — Completed 10-02 (async_initiate template overloads for use_future/use_awaitable/deferred; 25 tests pass, TSan clean)
progress:
  total_phases: 5
  completed_phases: 4
  total_plans: 11
  completed_plans: 10
  percent: 100
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-04)

**Core value:** A C++23 mDNS library that composes naturally with any executor or event loop — no owned threads, no hidden allocations, no C types leaking into user code. Truly standalone.
**Current focus:** Phase 10 — ASIO Completion Tokens

## Current Position

Phase: 10 of 11 (ASIO Completion Tokens) — COMPLETE
Plan: 02 (10-02 complete — async_initiate template overloads, completion token tests)
Status: Phase 10 complete
Last activity: 2026-03-04 — Completed 10-02 (async_initiate template overloads for use_future/use_awaitable/deferred; 25 tests pass, TSan clean)

Progress: [██████████] 100% (v2.0)

## Performance Metrics

**Velocity (v1.0 reference):**
- Total plans completed: 18
- Average duration: ~15 min
- Total execution time: ~4.5 hours

**v2.0:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 07-policy-unification | 1 | ~6 min | ~6 min |
| Phase 07-policy-unification-and-direct-construction P02 | 3 | 2 tasks | 5 files |
| Phase 07-policy-unification-and-direct-construction P03 | 573 | 2 tasks | 21 files |
| Phase 08-native-dns-protocol P01 | ~4 min | 1 task | 3 files |
| Phase 08-native-dns-protocol P02 | ~7 min | 2 tasks | 6 files |
| Phase 09-nativepolicy-standalone-networking P01 | ~5 min | 2 tasks | 4 files |
| Phase 09-nativepolicy-standalone-networking P02 | ~5 min | 2 tasks | 6 files |
| Phase 10-asio-completion-tokens P01 | 15 | 3 tasks | 14 files |
| Phase 10-asio-completion-tokens P02 | ~30 min | 2 tasks | 6 files |
| Phase 11-service-aggregation P01 | 10 | 1 tasks | 3 files |

## Accumulated Context

### Decisions

- Single unified `Policy` replaces dual `SocketPolicy`+`TimerPolicy` — less template noise, matches ASIO convention
- Throw + `error_code` construction (ASIO convention), drop `create()` factory
- ASIO completion tokens via `async_initiate`; evaluate `async_compose` at Phase 10 planning
- `NativePolicy` for standalone networking (`run()`/`poll()`), no ASIO in include chain
- Replace mjansson/mdns with native `dns_decode.h` (~200 LOC) — Phase 8 prerequisite for Phase 9
- RFC 6762 conflict resolution and PMR allocators deferred to v2.1 (not in REQUIREMENTS.md v2.0)
- `executor_type = asio::io_context &` (reference type) — concrete types store executor internally, matching ASIO convention
- MockSocket failure injection via static flag — avoids changing constructor signature while enabling error path testing
- detail::always_false moved to policy.h as the single concept header
- [Phase 07]: Public types own socket/timer as members; recv_loop borrows by reference — inverts old ownership model
- [Phase 07]: service_server exposes timer() for response timer and recv_timer() for recv loop timer as named accessors
- [Phase 07]: recv_loop public socket()/timer() accessors removed — public types access their own members directly
- [Phase 07]: MockTimer::fire() accessed via local timer variable — recv_loop no longer exposes timer() accessor
- [Phase 08]: read_dns_name produces dotted-label names without trailing dot (e.g. "_http._tcp.local"); existing parse_test uses find() so no regressions
- [Phase 08]: read_dns_name takes offset by value (not reference) — stateless decode from a fixed point, matching parse.cpp usage of meta.name_offset
- [Phase 08-02]: Owner name extraction is lenient (empty string on failure) — parse_test buffers use raw record data at name_offset=0, mjansson was also lenient
- [Phase 08-02]: Trailing dot stripped in querent/service_discovery stored name, not in read_dns_name — callers normalize to match no-trailing-dot convention
- [Phase 09-01]: NativeContext forward-declares NativeTimer; compute_next_timeout_ms/fire_expired_timers defined out-of-line in native_timer.h after full NativeTimer definition — breaks mutual include dependency cleanly
- [Phase 09-01]: compute_next_timeout_ms returns -1 when no timer has a pending handler (poll blocks indefinitely — avoids busy-polling when idle)
- [Phase 09-01]: expires_after drops pending handler silently without calling it (matches MockTimer semantics required by recv_loop)
- [Phase 09-02]: SO_REUSEPORT failure is non-fatal (warn, do not throw) — not universally supported and non-critical for correctness
- [Phase 09-02]: send() is synchronous sendto() — mDNS sends are tiny/infrequent, async complexity not warranted
- [Phase 09-02]: async_receive delegates to NativeContext.register_receive — context owns recvfrom dispatch, NativeSocket just arms it
- [Phase 10-asio-completion-tokens]: async_ prefix for all public entry-point methods; completion_handler fires via std::exchange for exactly-once semantics; results() accessor gets copy (not move) so it stays populated after completion fires
- [Phase 10-02]: std::move_only_function replaces std::function for m_on_completion — required for use_awaitable move-only coroutine handles; empty std::function must be checked before storing (truthy-but-throws wrapper otherwise)
- [Phase 10-02]: Work guard (w2) moved into final dispatch lambda — released AFTER handler executes, preventing premature io_context::run() return
- [Phase 10-02]: io.stop() in use_awaitable observer tests — observer::stop() leaves recv_loop running by design; explicit io.stop() needed for single-threaded test drain
- [Phase 11-service-aggregation]: resolved_service has no TTL field — plain aggregate value type; aggregate() inline in header; span overload is primary; SRV latest-wins for hostname/port

### Pending Todos

None.

### Blockers/Concerns

- Phase 9 (NativePolicy): Windows CI job does not exist yet — `SO_REUSEPORT`, `WSAPoll`, multicast bind cannot be verified without it. Add Windows CI as first task in Phase 9.
- Phase 10 (completion tokens): `async_compose` vs. hand-rolled `async_initiate` — decide at planning time, not mid-implementation.

## Session Continuity

Last session: 2026-03-04T17:42:01.559Z
Stopped at: Completed 11-01-PLAN.md (resolved_service struct, aggregate() with two-pass RFC 6763 correlation; 18 tests pass)
Resume file: None
