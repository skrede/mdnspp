---
phase: 10-asio-completion-tokens
plan: 01
subsystem: api
tags: [cpp23, mdns, async, callback, completion-handler, policy]

# Dependency graph
requires:
  - phase: 09-nativepolicy-standalone-networking
    provides: NativePolicy, NativeSocket, NativeTimer — all public types now work with both MockPolicy and NativePolicy
provides:
  - async_discover(type, completion_handler) on service_discovery<P>
  - async_query(name, qtype, completion_handler) on querent<P>
  - async_observe([completion_handler]) on observer<P>
  - async_start([completion_handler]) on service_server<P>
  - completion_handler type aliases on all four public types
affects: [10-02-PLAN.md — builds ASIO token layer on top of these callback methods]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "std::exchange(m_on_completion, nullptr) for exactly-once handler invocation"
    - "completion_handler = std::function<void(std::error_code, ...)> type alias on each public type"
    - "Completion fires at natural stop point: silence timeout (query-style) or stop() (long-lived)"

key-files:
  created: []
  modified:
    - include/mdnspp/service_discovery.h
    - include/mdnspp/querent.h
    - include/mdnspp/observer.h
    - include/mdnspp/service_server.h
    - include/mdnspp/native.h
    - tests/service_discovery_test.cpp
    - tests/querent_test.cpp
    - tests/observer_test.cpp
    - tests/service_server_test.cpp
    - tests/service_server_tsan_test.cpp
    - example/discover.cpp
    - example/query.cpp
    - example/observe.cpp
    - example/serve.cpp

key-decisions:
  - "results() accessor on service_discovery and querent receives a copy (not move) of m_results — accessor stays populated after completion handler fires"
  - "completion_handler on observer/service_server defaults to {} — async_observe()/async_start() with no args is fire-and-forget"
  - "Completion fires BEFORE m_response_timer.cancel()/m_loop.reset() in service_server::stop() — handler can safely inspect server state"
  - "silence timer must be fired manually (timer().fire()) in MockPolicy tests — MockTimer does not auto-fire"

patterns-established:
  - "async_ prefix for all public entry-point methods (aligns with ASIO naming convention)"
  - "std::exchange(handler, nullptr) guards: exactly-once invocation even if stop() is called concurrently or twice"

requirements-completed: [API-09, API-10]

# Metrics
duration: 15min
completed: 2026-03-04
---

# Phase 10 Plan 01: Async API (Callback Completion) Summary

**Four public types gain async_ methods with callback completions: discover/query fire on silence timeout with (error_code, results); observe/start fire on stop() with (error_code)**

## Performance

- **Duration:** ~15 min
- **Started:** 2026-03-04T15:50:00Z
- **Completed:** 2026-03-04T16:07:49Z
- **Tasks:** 3
- **Files modified:** 14

## Accomplishments
- All four public types transformed to async_ API: `async_discover`, `async_query`, `async_observe`, `async_start`
- Old `discover()`, `query()`, `start()` removed — calling them is a compile error (clean break for v2.0)
- Completion callbacks fire at the correct point: silence timeout for query-style types, `stop()` for long-lived types
- `results()` accessor preserved and stays populated after completion (handler receives a copy, not a move)
- Default-empty completion handlers allow fire-and-forget usage without callbacks
- New tests verify callback semantics per type; all 13 tests pass (11 MockPolicy + 2 ASIO/TSan)

## Task Commits

Each task was committed atomically:

1. **Task 1: Transform query-style types (service_discovery, querent)** - `31c1f09` (feat)
2. **Task 2: Transform long-lived types (observer, service_server)** - `af2531c` (feat)
3. **Task 3: Update all tests and examples to async_ API** - `459b4be` (test)

## Files Created/Modified
- `include/mdnspp/service_discovery.h` - Renamed discover() to async_discover(type, completion_handler); added m_on_completion; completion fires at silence timeout or stop()
- `include/mdnspp/querent.h` - Renamed query() to async_query(name, qtype, completion_handler); identical completion pattern to service_discovery
- `include/mdnspp/observer.h` - Renamed start() to async_observe([completion_handler={}]); completion fires in stop() before return
- `include/mdnspp/service_server.h` - Renamed start() to async_start([completion_handler={}]); completion fires in stop() before timer cancel/loop reset
- `include/mdnspp/native.h` - Updated usage comment to show async_observe()
- `tests/service_discovery_test.cpp` - Updated all scenarios; added async_discover callback test (uses timer().fire())
- `tests/querent_test.cpp` - Updated all scenarios; added async_query callback test (uses timer().fire())
- `tests/observer_test.cpp` - Updated all scenarios; added async_observe callback test and idempotency test
- `tests/service_server_test.cpp` - Updated all scenarios; added async_start callback test and idempotency test
- `tests/service_server_tsan_test.cpp` - Updated start() to async_start()
- `example/discover.cpp` - Updated to async_discover() with completion callback
- `example/query.cpp` - Updated to async_query() with completion callback
- `example/observe.cpp` - Updated to async_observe() fire-and-forget
- `example/serve.cpp` - Updated to async_start() fire-and-forget

## Decisions Made
- results() accessor receives a copy of m_results (not move): the accessor remains populated after the completion handler fires. mDNS results are tiny, so the copy overhead is negligible.
- Default-empty completion handler (`= {}`) on observer::async_observe() and service_server::async_start() enables fire-and-forget usage without callback — natural for NativePolicy users who call stop() manually.
- Completion fires BEFORE cancel/reset in service_server::stop(): the handler sees server state before teardown.
- MockTimer requires manual `timer().fire()` to trigger silence completion — MockSocket drains the queue synchronously but the timer only fires when `fire()` is called. Test comments and assertions updated accordingly.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Test comment and assertion timing incorrect for MockPolicy callback tests**
- **Found during:** Task 3 (test execution)
- **Issue:** New callback tests (async_discover/async_query fires) assumed MockSocket drains synchronously and silence fires immediately. MockTimer requires explicit `timer().fire()` call.
- **Fix:** Added `sd.timer().fire()` / `q.timer().fire()` before the THEN assertions; updated WHEN clause wording to accurately describe the two-step sequence.
- **Files modified:** tests/service_discovery_test.cpp, tests/querent_test.cpp
- **Verification:** All 11 tests pass after fix.
- **Committed in:** 459b4be (Task 3 commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 - Bug)
**Impact on plan:** Minor test correction. No behavioral change to production code. Timer().fire() is the correct way to trigger silence callbacks in MockPolicy tests — consistent with existing service_server timer tests.

## Issues Encountered
None — plan executed smoothly once MockTimer semantics were corrected in the callback tests.

## Next Phase Readiness
- Callback API is complete and tested against MockPolicy and AsioPolicy
- Plan 10-02 layers ASIO completion token (`async_initiate`) template support on top of these callback methods
- The `m_on_completion` path is the foundation for token dispatch in Plan 02

---
*Phase: 10-asio-completion-tokens*
*Completed: 2026-03-04*
