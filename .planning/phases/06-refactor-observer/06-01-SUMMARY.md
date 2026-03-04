---
phase: 06-refactor-observer
plan: 01
subsystem: observer
tags: [tdd, policy-based, recv_loop, lifecycle, callback-safe-stop]
dependency_graph:
  requires:
    - recv_loop<S,T> (02-02)
    - detail::walk_dns_frame (dns_wire.h, 03-01)
    - MockSocketPolicy/MockTimerPolicy (01-03, 02-01)
  provides:
    - observer<S,T> class template with create/start/stop lifecycle
    - BDD test coverage for observer (6 scenarios)
  affects:
    - include/mdnspp/observer.h (rewritten)
    - tests/observer_test.cpp (new)
    - tests/CMakeLists.txt (observer_test registered)
tech_stack:
  added: []
  patterns:
    - policy-based <S,T> template (mirrors service_server pattern)
    - create() factory returning std::expected<observer, mdns_error>
    - recv_loop composition via std::unique_ptr
    - std::atomic<bool> for idempotent stop (callback-safe)
    - walk_dns_frame for packet-to-record dispatch
key_files:
  created:
    - tests/observer_test.cpp
  modified:
    - include/mdnspp/observer.h
    - tests/CMakeLists.txt
decisions:
  - observer is movable before start() to satisfy std::expected<T,E> constructibility requirements; moving after start() is a logic error (asserted via m_loop==nullptr check in move ctor)
  - stop() sets atomic flag only; does NOT reset m_loop — callback-safe stop pattern prevents use-after-free when stop() is called from within the record callback
  - destructor stores m_stopped=true then resets m_loop — safe because destructor is never called from within recv_loop callback chain
  - silence timeout set to 24*365h — run-until-stop semantics, identical to service_server pattern
  - socket() accessor delegates to m_loop->socket() after start() — mirrors service_server::socket() pattern for test inspection
metrics:
  duration: 3 min
  completed_date: 2026-03-04
  tasks_completed: 2
  files_modified: 3
---

# Phase 6 Plan 01: observer<S,T> class template with perpetual receive and callback delivery Summary

observer<S,T> implemented as policy-based class template composing recv_loop<S,T> for perpetual multicast listening, with callback-safe atomic stop and full BDD test coverage (6 scenarios, all passing).

## What Was Built

The `observer<S, T>` class template replaces the Phase 1 stub in `include/mdnspp/observer.h`. It follows the same policy-based lifecycle pattern established by `service_server<S, T>` in Phase 5, but is simpler: pure receive-only, one timer (no response delay), no strand.

**Key components:**

- `create(socket, timer, callback)` factory returning `std::expected<observer, mdns_error>`
- `start()` creates `recv_loop<S,T>` with 24-year silence timeout (run-until-stop) and arms it; moves socket and timer into the loop
- `stop()` sets `m_stopped.exchange(true)` atomically — idempotent, callback-safe (does NOT destroy the loop)
- `~observer()` sets the stop flag then resets the recv_loop — the only safe teardown point
- `on_packet()` calls `detail::walk_dns_frame()` and delivers each parsed record with the sender endpoint
- `socket()` test accessor delegates to `m_loop->socket()` after start, to `m_socket` before

## Tests

6 BDD scenarios in `tests/observer_test.cpp`:

1. **packet delivery** — PTR record delivered with correct sender endpoint
2. **multiple packets** — PTR + A records from separate packets both delivered
3. **stop idempotency** — second stop() call does not crash or assert
4. **lifecycle** — create/start/stop with empty queue; callback never invoked
5. **callback-safe stop** — stop() called from within the record callback; no deadlock
6. **malformed packet** — 5-byte truncated packet; no crash, no records delivered

All 9 tests pass (8 existing + 1 new observer_test).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Added move constructor to enable std::expected<observer, mdns_error>**
- **Found during:** Task 2 (GREEN - implementation)
- **Issue:** The plan specified "Non-copyable, non-movable (delete all four)" but `std::expected<T, E>` requires `is_constructible_v<T, Args...>` to be true for its value constructor, and requires either move or copy constructibility to hold the value. With all four deleted, the `create()` factory could not return `std::expected<observer, mdns_error>`.
- **Fix:** Added a move constructor (move-only before start, asserted via `m_loop == nullptr`). Move-assign remains deleted. This is the same "movable before start" pattern as service_server, and is explicitly referenced as "RESEARCH open question 2" in the plan.
- **Files modified:** `include/mdnspp/observer.h`
- **Commit:** a856a40

## Self-Check: PASSED

All files present and all commits verified:
- FOUND: include/mdnspp/observer.h
- FOUND: tests/observer_test.cpp
- FOUND: tests/CMakeLists.txt
- FOUND: ac7b1db (RED commit - failing tests)
- FOUND: a856a40 (GREEN commit - implementation)
