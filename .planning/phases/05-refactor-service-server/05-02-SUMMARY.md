---
phase: 05-refactor-service-server
plan: 02
subsystem: mdns-server
tags: [cpp23, template, policy-based, recv_loop, rfc6762, mock, catch2]

# Dependency graph
requires:
  - phase: 05-01
    provides: service_info.h, build_dns_response(), MockSocketPolicy enqueue overload
  - phase: 04-01
    provides: recv_loop<S,T> class template, service_discovery pattern for create()
  - phase: 02-02
    provides: recv_loop<S,T> implementation
  - phase: 02-01
    provides: MockTimerPolicy with fire() test control

provides:
  - "service_server<S,T> class template with create()/start()/stop() lifecycle"
  - "RFC 6762 20-500ms random response delay via m_response_timer"
  - "recv_loop-based continuous query listener (silence timeout = 24*365h)"
  - "8 BDD scenarios covering full query-receive-delay-respond flow"

affects:
  - "05-03-service-server-tsan"
  - "06-asio-wiring"

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "service_server<S,T> follows service_discovery<S,T> create() factory pattern"
    - "Dual timer ownership: m_response_timer (response delay) + m_recv_timer (passed to recv_loop)"
    - "Atomic bool m_stopped for idempotent stop() — same pattern as recv_loop"
    - "Random delay via std::mt19937 seeded with std::random_device"
    - "Timer copy for response_timer, move for recv_timer — intentional ownership split"

key-files:
  created: []
  modified:
    - "include/mdnspp/service_server.h"
    - "tests/service_server_test.cpp"

key-decisions:
  - "service_server takes S by value to m_socket plus two T copies (response_timer copy, recv_timer move) — enables independent timer lifecycles without sharing state"
  - "recv_loop silence timeout set to 24*365h — server runs until explicit stop(), not on silence"
  - "Move constructor/assignment assert m_loop == nullptr — moving a started server is a logic error caught at runtime"
  - "on_query re-uses m_response_timer per query — single outstanding response timer; last query wins if multiple arrive before timer fires"
  - "send_response checks for empty build_dns_response return — gracefully handles unmatched qtypes or missing address fields"

patterns-established:
  - "Timer dual-copy pattern: copy for one use, move for another — established for service_server"
  - "Test accessor socket()/timer() on service classes — enables inspection of internal copies without friendship"

requirements-completed: [BEHAV-03, BEHAV-04]

# Metrics
duration: 3min
completed: 2026-03-04
---

# Phase 05 Plan 02: service_server<S,T> Summary

**Policy-based mDNS responder with create()/start()/stop() lifecycle, recv_loop query listening, and RFC 6762 20-500ms random response delay verified via MockTimerPolicy**

## Performance

- **Duration:** 3 min
- **Started:** 2026-03-04T04:23:51Z
- **Completed:** 2026-03-04T04:25:42Z
- **Tasks:** 2 (TDD: RED + GREEN per task)
- **Files modified:** 2

## Accomplishments

- Replaced single-param service_server stub with full `service_server<S, T>` class template
- Implemented create() factory returning `std::expected<service_server, mdns_error>` (same pattern as service_discovery)
- start() constructs recv_loop with 24-year silence timeout (run-until-stop semantics), on_query arms response timer with 20-500ms random delay per RFC 6762
- stop() is idempotent via `std::atomic<bool>`, cancels response timer, destroys recv_loop
- 8 BDD scenarios with MockSocketPolicy/MockTimerPolicy covering: create, lifecycle, PTR response, A response, RFC 6762 timing (no response before timer fires), stop-cancellation, sender endpoint routing
- Zero mutex usage and no mdns_base inheritance — BEHAV-03 and BEHAV-04 satisfied

## Task Commits

TDD cycle (RED then GREEN):

1. **Task 1+2 RED: Failing tests** - `dcbc413` (test)
   - Added 8 service_server BDD scenarios to service_server_test.cpp
   - Build failed: old stub had single template param, no create()
2. **Task 1 GREEN: Implementation** - `2baa2bb` (feat)
   - Full service_server<S,T> replacing stub; all 40 assertions pass

## Files Created/Modified

- `/home/skrede/Workspace/mdnspp/include/mdnspp/service_server.h` — Full class template: create(), start(), stop(), on_query(), send_response(), socket()/timer() test accessors, dual timer ownership
- `/home/skrede/Workspace/mdnspp/tests/service_server_test.cpp` — Extended with 8 BDD scenarios for server behavior (6 existing build_dns_response scenarios retained + 8 new server scenarios = 15 total)

## Decisions Made

- **Dual timer ownership**: Constructor takes one T by value, copies it into m_response_timer (response delay), moves it into m_recv_timer (passed to recv_loop). This gives service_server exclusive control over response timing while recv_loop independently manages silence detection.
- **on_query re-arms single timer**: Multiple queries arriving before the timer fires result in "last query wins" — the previous timer is cancelled by expires_after() when a new one is armed. This matches real-world mDNS behavior where rapid queries coalesce.
- **Move guards**: Move constructor/assignment assert m_loop == nullptr to catch logic errors at runtime rather than silently invalidating callback captures.
- **recv_loop silence timeout = 24*365h**: Server continues running until stop() is called explicitly, not on traffic absence. Avoids complexity of restart logic.

## Deviations from Plan

None - plan executed exactly as written. All 8 required BDD scenarios implemented. Both required commits (test RED, feat GREEN) produced.

## Issues Encountered

None - implementation compiled and all tests passed on first build attempt.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- service_server<S,T> is fully implemented and tested with mocks
- Ready for Plan 05-03: TSan integration test with AsioSocketPolicy to verify BEHAV-03 (strand safety in real async context)
- The socket() test accessor enables sent_packet inspection in future integration tests

---
*Phase: 05-refactor-service-server*
*Completed: 2026-03-04*
