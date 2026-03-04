---
phase: 04-refactor-service-discovery-and-querent
plan: 02
subsystem: api
tags: [dns, mdns, querent, cpp23, expected, policy-based, tdd]

# Dependency graph
requires:
  - phase: 04-refactor-service-discovery-and-querent (plan 01)
    provides: src/mdnspp/dns_wire.h with walk_dns_frame, build_dns_query, encode_dns_name; service_discovery<S,T> pattern
  - phase: 02-recv-loop-and-asio-socket-policy
    provides: recv_loop<S,T>, MockSocketPolicy, MockTimerPolicy
  - phase: 03-record-parser-free-functions
    provides: parse::record() free function, mdns_record_variant

provides:
  - include/mdnspp/querent.h as full <S,T> template with create() factory and query(name, qtype) method
  - tests/querent_test.cpp with 6 BDD test scenarios covering all querent behaviors
  - Phase 4 complete — service_discovery and querent both verified against all 4 ROADMAP success criteria

affects:
  - 05 (integration — querent<AsioSocketPolicy, AsioTimerPolicy> production use)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - querent<S,T> mirrors service_discovery<S,T>: private constructor, create() factory, query() composes recv_loop locally
    - query(std::string_view name, uint16_t qtype) — flat DNS-idiomatic parameters, not a query struct
    - recv_loop constructed with copies of m_socket and m_timer in query() — same pattern as discover()

key-files:
  created:
    - tests/querent_test.cpp
  modified:
    - include/mdnspp/querent.h
    - tests/CMakeLists.txt

key-decisions:
  - "query() signature is query(std::string_view name, uint16_t qtype) — flat DNS-idiomatic parameters; caller specifies QNAME and QTYPE directly"
  - "recv_loop constructed with copies of m_socket and m_timer inside query() — allows multiple query() calls on same instance; mirrors service_discovery::discover() pattern"
  - "querent<S,T> exposes socket() test accessor — same pattern as service_discovery; needed to inspect sent_packets from inside m_socket copy"

patterns-established:
  - "Service template pattern: private constructor + create() factory + method composing local recv_loop from copies of m_socket/m_timer"

requirements-completed: [BEHAV-01, API-03, TEST-01]

# Metrics
duration: 4min
completed: 2026-03-04
---

# Phase 4 Plan 02: Querent Summary

**querent<S,T> class template with create() factory and query(name, qtype) returning accumulated std::expected<vector<mdns_record_variant>, mdns_error>, completing Phase 4**

## Performance

- **Duration:** 4 min (approx — TDD RED at 04:10, GREEN at 04:12)
- **Started:** 2026-03-04T04:10:55Z
- **Completed:** 2026-03-04T04:12:29Z
- **Tasks:** 2 (Task 1: TDD implementation; Task 2: human verification)
- **Files modified:** 3

## Accomplishments

- Rewrote `include/mdnspp/querent.h` from a `static_assert(always_false<S>)` stub to a full `<SocketPolicy S, TimerPolicy T>` template with private constructor, `create()` factory returning `std::expected<querent, mdns_error>`, and `query(string_view name, uint16_t qtype)` method that sends a DNS query and accumulates records via locally-composed recv_loop
- Created `tests/querent_test.cpp` with 6 BDD test scenarios (create factory, A-record accumulation, query packet format, multi-record accumulation, multiple query() calls, malformed-record skipping)
- All 4 Phase 4 ROADMAP success criteria verified by human: discover() and query() return populated vectors, create() factories present in both types, neither type inherits from mdns_base, all 6 test suites pass

## Task Commits

1. **Task 1 (RED): Add failing querent tests** - `7017444` (test)
2. **Task 1 (GREEN): Implement querent<S,T> class template** - `e51a61d` (feat)
3. **Task 2: Phase 4 human verification** - approved (no additional commit needed)

## Files Created/Modified

- `include/mdnspp/querent.h` — Full <S,T> template replacing Phase 1 stub; private constructor, create() factory, query(name, qtype) method, socket() test accessor
- `tests/querent_test.cpp` — 6 BDD scenarios: create() factory, A-record return, sent-packet format verification, multi-record accumulation, multiple query() calls, malformed-record skipping
- `tests/CMakeLists.txt` — Added make_test(querent_test) after service_discovery_test

## Decisions Made

- query() uses flat parameters `(std::string_view name, uint16_t qtype)` — DNS-idiomatic; the caller specifies QNAME and QTYPE directly, matching how DNS queries are naturally expressed (e.g., `query("myhost.local.", 1)` for A record)
- recv_loop is constructed with copies of m_socket and m_timer inside query() — identical pattern to service_discovery::discover(); this satisfies recv_loop's non-copyable/non-movable constraint (it's a local variable) while allowing multiple query() calls on the same querent instance
- socket() test accessor added to querent — needed to inspect sent_packets from the internal m_socket copy; mirrors the recv_loop::timer() and service_discovery::socket() patterns already established

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 4 is complete: both service_discovery<S,T> and querent<S,T> satisfy all 4 ROADMAP success criteria
- All 6 test suites pass: log_test, concept_conformance_test, recv_loop_test, parse_test, service_discovery_test, querent_test
- Phase 5 (service_server refactor) can proceed — service_discovery and querent patterns are established
- service_server<AsioSocketPolicy, AsioTimerPolicy> integration readiness is the next milestone

## Self-Check

- FOUND: include/mdnspp/querent.h
- FOUND: tests/querent_test.cpp
- FOUND commit: 7017444
- FOUND commit: e51a61d
- All 6 test suites pass (100%) — verified by human at checkpoint

---
*Phase: 04-refactor-service-discovery-and-querent*
*Completed: 2026-03-04*
