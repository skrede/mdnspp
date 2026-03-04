---
phase: 09-nativepolicy-standalone-networking
plan: 01
subsystem: networking
tags: [native, posix, eventfd, poll, timer, event-loop]

# Dependency graph
requires:
  - phase: 08-native-dns-protocol
    provides: dns_wire.h decode infrastructure used by NativeSocket (Phase 09-02+)
provides:
  - NativeContext: poll-based event loop with stop-wakeup fd (eventfd/pipe/loopback-UDP)
  - NativeTimer: deadline timer satisfying TimerLike; register/deregister with NativeContext
  - Platform aliases: native_socket_t, invalid_socket, close_socket, poll_sockets
  - winsock_guard RAII class (no-op on POSIX, WSAStartup/WSACleanup on Windows)
affects:
  - 09-02 (NativeSocket must register_socket/register_receive with NativeContext)
  - 09-03 (NativePolicy bundles NativeContext, NativeSocket, NativeTimer)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Circular-dependency broken by forward-declaring NativeTimer in native_context.h; out-of-line method bodies defined in native_timer.h after full NativeTimer definition"
    - "Platform wakeup mechanism selected at compile time: eventfd (Linux), self-pipe (POSIX), loopback UDP (Windows)"
    - "TDD: RED test commits before implementation, GREEN commits after all tests pass"

key-files:
  created:
    - include/mdnspp/native/native_context.h
    - include/mdnspp/native/native_timer.h
    - tests/native_timer_test.cpp
  modified:
    - tests/CMakeLists.txt

key-decisions:
  - "Out-of-line NativeContext::compute_next_timeout_ms and fire_expired_timers defined in native_timer.h (not native_context.h) to break mutual include dependency cleanly"
  - "NativeContext::dispatch_receive() ignores EAGAIN/EWOULDBLOCK silently — non-blocking socket, poll already confirmed data is ready so this is an edge case only"
  - "compute_next_timeout_ms returns -1 (block indefinitely) when no timer has a pending handler — avoids busy-polling when there is nothing to fire"

patterns-established:
  - "Native headers: no ASIO includes anywhere; only POSIX/Win32 system headers"
  - "expires_after drops pending handler silently (NativeTimer matches MockTimer semantics required by recv_loop)"
  - "cancel fires handler with operation_canceled; no-op if nothing pending"

requirements-completed: [NET-02, NET-03, NET-04, NET-06]

# Metrics
duration: 5min
completed: 2026-03-04
---

# Phase 9 Plan 01: NativeContext Event Loop and NativeTimer Summary

**Poll-based standalone event loop (NativeContext) with platform wakeup via eventfd/pipe/loopback-UDP, plus NativeTimer satisfying TimerLike using steady_clock deadlines and silent drop on expires_after.**

## Performance

- **Duration:** ~5 min
- **Started:** 2026-03-04T14:39:56Z
- **Completed:** 2026-03-04T14:44:53Z
- **Tasks:** 2 (Task 1: NativeContext, Task 2: NativeTimer TDD)
- **Files modified:** 4

## Accomplishments

- NativeContext: poll() event loop with run()/poll_one()/stop()/restart(), stop-wakeup fd (eventfd on Linux, self-pipe on POSIX, loopback UDP socket on Windows), register/deregister for NativeSocket and NativeTimer
- NativeTimer: satisfies TimerLike, expires_after silently drops handler (matching MockTimer for recv_loop correctness), cancel fires operation_canceled, fire_if_expired used by NativeContext
- Platform type aliases (native_socket_t, invalid_socket, close_socket, poll_sockets) and winsock_guard RAII class support both POSIX and Windows without ASIO
- All 10 native_timer_test cases pass; concept_conformance_test continues to pass

## Task Commits

1. **Task 1: NativeContext event loop with platform abstractions** - `4188716` (feat)
2. **Task 2 RED: Failing tests for NativeTimer** - `b7a6263` (test)
3. **Task 2 GREEN: NativeTimer satisfying TimerLike** - `214bb34` (feat)

## Files Created/Modified

- `include/mdnspp/native/native_context.h` - Event loop, platform aliases, winsock_guard, stop-wakeup fd, dispatch_receive, timer scheduling
- `include/mdnspp/native/native_timer.h` - NativeTimer + out-of-line NativeContext timer method bodies + static_assert(TimerLike<NativeTimer>)
- `tests/native_timer_test.cpp` - 10 TDD tests covering all NativeTimer semantics
- `tests/CMakeLists.txt` - Added native_timer_test target

## Decisions Made

- **Mutual dependency**: NativeContext forward-declares NativeTimer; compute_next_timeout_ms and fire_expired_timers are defined out-of-line in native_timer.h after NativeTimer is fully visible. This is idiomatic C++ (analogous to smart pointer headers).
- **compute_next_timeout_ms returns -1**: When no timer has a pending handler, poll() blocks indefinitely — avoids busy-polling when idle.
- **EAGAIN silently ignored in dispatch_receive**: poll() guarantees POLLIN before dispatch_receive is called; EAGAIN is an edge case, silently returning is correct POSIX behaviour.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] std::max call with mixed chrono/long long types failed to compile**
- **Found during:** Task 2 GREEN (compile error)
- **Issue:** `std::max(diff.count(), 0LL)` — diff.count() type ambiguity with clang
- **Fix:** Replaced with explicit ternary: `raw > 0 ? raw : 0`
- **Files modified:** include/mdnspp/native/native_timer.h
- **Verification:** native_timer_test builds and all 10 tests pass
- **Committed in:** 214bb34 (Task 2 feat commit)

---

**Total deviations:** 1 auto-fixed (Rule 1 - compile bug)
**Impact on plan:** Minimal fix to a type-safety issue; no semantic change.

## Issues Encountered

None beyond the auto-fixed compile error above.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- NativeContext and NativeTimer are complete and tested; NativeSocket (Plan 09-02) can now call register_socket/register_receive to hook into the event loop.
- No blockers. Windows CI still absent (noted in STATE.md blockers) but headers have correct #ifdef guards.

---
*Phase: 09-nativepolicy-standalone-networking*
*Completed: 2026-03-04*
