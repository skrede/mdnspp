---
phase: 10-asio-completion-tokens
plan: 02
subsystem: api
tags: [cpp23, mdns, async, asio, completion-token, use_future, use_awaitable, deferred, tsan]

# Dependency graph
requires:
  - phase: 10-asio-completion-tokens plan 01
    provides: async_discover/async_query/async_observe/async_start with callback completions on all four public types

provides:
  - async_initiate template overloads for async_discover, async_query, async_observe, async_start
  - use_future path: returns std::future<results> that resolves after io.run()
  - use_awaitable path: co_await suspends until stop() is called
  - deferred path: operation does not initiate I/O until launched
  - TSan-clean handler dispatch via asio::dispatch with associated allocator
  - asio_completion_token_test.cpp with 7 integration tests

affects: [phase 11 - any future async or ergonomics work]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "asio::async_initiate pattern for ASIO completion token support on all four public types"
    - "std::move_only_function for m_on_completion member — supports move-only coroutine handlers"
    - "#ifdef ASIO_STANDALONE / #ifndef ASIO_STANDALONE guard pattern for conditional API disambiguation"
    - "Work guard moved into final dispatch lambda (w2) to prevent premature io_context::run() return"
    - "do_discover/do_query/do_observe/do_start private helpers to eliminate duplication between template and non-template paths"
    - "Empty std::function check before storing in move_only_function — prevents truthy-but-throws wrapper"

key-files:
  created:
    - tests/asio_completion_token_test.cpp
  modified:
    - include/mdnspp/service_discovery.h
    - include/mdnspp/querent.h
    - include/mdnspp/observer.h
    - include/mdnspp/service_server.h
    - tests/CMakeLists.txt

key-decisions:
  - "Non-template std::function callback overloads guarded by #ifndef ASIO_STANDALONE — prevents ambiguity with template overloads that also accept plain lambdas"
  - "std::move_only_function replaces std::function for m_on_completion members — required for use_awaitable handlers which are move-only (coroutine handles)"
  - "Work guard (w2) moved into final dispatch lambda — released AFTER handler executes, not BEFORE, preventing premature io_context::run() return"
  - "Zero-arg async_observe()/async_start() overloads added for ASIO users as fire-and-forget equivalents (delegate to asio::detached)"
  - "TSan/use_awaitable test uses io.stop() after co_await returns — observer's recv_loop keeps io_context alive by design, explicit stop needed for test drain"
  - "Empty std::function guard before storing in move_only_function: if (on_done) m_on_completion = std::move(on_done) — empty std::function becomes truthy-but-throws wrapper in move_only_function"

patterns-established:
  - "ASIO_STANDALONE as include guard for ASIO-only public API surface — NativePolicy users never see ASIO headers"
  - "async_initiate initiation lambda stores type-erased handler in move_only_function; fires via asio::dispatch for executor and TSan safety"

requirements-completed: [API-09, API-11, API-12, API-13]

# Metrics
duration: 30min
completed: 2026-03-04
---

# Phase 10 Plan 02: ASIO Completion Tokens Summary

**ASIO completion token support (use_future, use_awaitable, deferred) added to all four public types via async_initiate, with move_only_function for move-only coroutine handlers and TSan-clean dispatch**

## Performance

- **Duration:** ~30 min
- **Started:** 2026-03-04T16:10:00Z
- **Completed:** 2026-03-04T16:40:00Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments
- All four public types gain template `async_` overloads using `asio::async_initiate` — `use_future`, `use_awaitable`, `deferred`, and plain lambdas all work through the single template
- Non-template `std::function` callback overloads guarded by `#ifndef ASIO_STANDALONE` — no ambiguity, NativePolicy unaffected
- Private `do_discover`/`do_query`/`do_observe`/`do_start` helpers extracted to avoid code duplication between template and non-template paths
- `m_on_completion` changed to `std::move_only_function` — supports move-only coroutine handles from `use_awaitable` without copy-constructibility requirement
- 7 integration tests in `asio_completion_token_test.cpp`: `use_future` (service_discovery + querent), `use_awaitable` (observer with co_await), `deferred` (service_discovery), callbacks from separate thread (observer + service_server), TSan test
- All 25 tests pass: 11 non-ASIO (MockPolicy) + 14 ASIO (including 7 new completion token tests)
- TSan clean: no data races reported under `-fsanitize=thread`

## Task Commits

Each task was committed atomically:

1. **Task 1: Add async_initiate template overloads to all four public types** - `1bcdff3` (feat)
2. **Task 2: Create ASIO completion token integration tests + header correctness fixes** - `018cec6` (feat)

## Files Created/Modified
- `include/mdnspp/service_discovery.h` - Added #ifdef ASIO_STANDALONE guards, async_initiate template overload, do_discover() private helper, move_only_function m_on_completion
- `include/mdnspp/querent.h` - Same pattern as service_discovery; do_query() helper
- `include/mdnspp/observer.h` - Added async_initiate template overload + zero-arg fire-and-forget; do_observe() helper; move_only_function m_on_completion
- `include/mdnspp/service_server.h` - Same pattern as observer; do_start() helper
- `tests/asio_completion_token_test.cpp` - 7 integration tests: use_future (×2), use_awaitable, deferred, callback (×2), TSan
- `tests/CMakeLists.txt` - Added make_asio_test(asio_completion_token_test)

## Decisions Made
- `std::move_only_function` for `m_on_completion`: required for `use_awaitable` handlers which are move-only (coroutine resumption handles). Public `completion_handler` type alias remains `std::function<>` for user-facing API.
- Work guard `w2` moved into final dispatch lambda: the work guard must live until after the handler executes, not just until it is dispatched. Moving it into the inner lambda ensures correct io_context lifetime.
- `io.stop()` in use_awaitable test: `observer::stop()` does not reset the recv_loop (callback-safe design). The recv_loop keeps the io_context alive. Explicit `io.stop()` after `co_await` is the correct pattern for single-threaded test drain.
- Empty `std::function` guard: `if (on_done) m_on_completion = std::move(on_done)` prevents wrapping an empty `std::function` in `move_only_function` — an empty `std::function` becomes a truthy-but-throws wrapper when stored in `move_only_function`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] move_only_function wraps empty std::function as truthy callable**
- **Found during:** Task 2 (running MockPolicy tests)
- **Issue:** Assigning an empty `std::function` to `std::move_only_function` produces a truthy wrapper that throws `std::bad_function_call` when invoked. Tests calling `async_start()` with no argument then `stop()` crashed.
- **Fix:** Changed `m_on_completion = std::move(on_done)` to `if (on_done) m_on_completion = std::move(on_done)` in all four non-template overloads. Also changed `m_on_completion` member type from `std::function` to `std::move_only_function` to support move-only handlers.
- **Files modified:** all four public type headers
- **Verification:** All 11 non-ASIO tests pass without crashes.
- **Committed in:** `018cec6` (Task 2 commit)

**2. [Rule 1 - Bug] Work guard released before handler executes — premature io_context drain**
- **Found during:** Task 2 (ASIO callback tests hanging)
- **Issue:** Work guard `w` was captured in outer `m_on_completion` lambda but destroyed when that lambda returned (after dispatching). The dispatch was queued but `w` was gone, allowing `io_context::run()` to potentially return before the dispatched handler ran.
- **Fix:** Move the work guard into the final dispatch lambda (`w2 = std::move(w)`) so it is released only after the handler executes.
- **Files modified:** all four public type headers
- **Verification:** ASIO callback tests pass without io_context drain issues; TSan clean.
- **Committed in:** `018cec6` (Task 2 commit)

**3. [Rule 2 - Missing Critical] Zero-arg async_observe()/async_start() overloads for ASIO fire-and-forget**
- **Found during:** Task 2 (build errors in examples and tsan_test)
- **Issue:** Existing code (examples, service_server_tsan_test) calls `async_start()` and `async_observe()` with no argument. With ASIO enabled, the template overload requires exactly one argument (the token). Build errors.
- **Fix:** Added zero-arg overloads inside `#ifdef ASIO_STANDALONE` that delegate to `async_observe(asio::detached)` / `async_start(asio::detached)`.
- **Files modified:** observer.h, service_server.h
- **Verification:** All ASIO builds succeed; existing tsan_test and examples compile and pass.
- **Committed in:** `018cec6` (Task 2 commit)

---

**Total deviations:** 3 auto-fixed (2 Rule 1 - Bug, 1 Rule 2 - Missing Critical)
**Impact on plan:** All three auto-fixes required for correctness and compilability. No scope creep.

## Issues Encountered
- `use_awaitable` test required `io.stop()` after `co_await` returns because `observer::stop()` intentionally leaves the recv_loop running (callback-safe design). This is a known architectural property documented in observer.h — not a bug. The test pattern (`io.stop()` after awaited op completes) is the correct ASIO idiom for single-threaded tests against observers.

## Next Phase Readiness
- ASIO completion token support complete for all four public types
- All three token types (use_future, use_awaitable, deferred) tested and TSan clean
- Phase 10 plans complete — library has full callback + ASIO token async API surface
- Ready for Phase 11 (whatever comes next in the roadmap)

---
*Phase: 10-asio-completion-tokens*
*Completed: 2026-03-04*
