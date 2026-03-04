---
phase: 07-policy-unification-and-direct-construction
plan: 03
subsystem: tests-examples-cleanup
tags: [migration, tests, examples, cleanup, policy-api]
dependency_graph:
  requires: [07-01, 07-02]
  provides: [clean-api-surface, no-legacy-headers]
  affects: [all-consumers]
tech_stack:
  added: []
  patterns: [MockPolicy-direct-construction, AsioPolicy-direct-construction, error-code-constructor-testing]
key_files:
  created: []
  modified:
    - tests/concept_conformance_test.cpp
    - tests/recv_loop_test.cpp
    - tests/observer_test.cpp
    - tests/service_discovery_test.cpp
    - tests/querent_test.cpp
    - tests/service_server_test.cpp
    - tests/service_info_test.cpp
    - tests/asio_conformance_test.cpp
    - tests/service_server_tsan_test.cpp
    - example/observe.cpp
    - example/discover.cpp
    - example/query.cpp
    - example/serve.cpp
    - include/mdnspp/service_info.h
    - CMakeLists.txt
  deleted:
    - include/mdnspp/socket_policy.h
    - include/mdnspp/timer_policy.h
    - include/mdnspp/testing/mock_socket_policy.h
    - include/mdnspp/testing/mock_timer_policy.h
    - include/mdnspp/asio/asio_socket_policy.h
    - include/mdnspp/asio/asio_timer_policy.h
decisions:
  - "MockTimer::fire() accessed via local timer variable — recv_loop no longer exposes timer() accessor"
  - "service_info_test.cpp migrated alongside main test files to avoid lingering MockSocketPolicy usage"
metrics:
  duration_seconds: 573
  tasks_completed: 2
  files_changed: 21
  completed_date: "2026-03-04"
---

# Phase 7 Plan 03: Test Migration and Old Header Removal Summary

Migrate all consumers (tests + examples) to the unified Policy API, delete 6 legacy headers, and leave the codebase with zero references to the old dual-policy names. All 11 tests pass.

## Tasks Completed

### Task 1: Migrate all unit tests to unified MockPolicy API

Migrated 7 test files (concept_conformance_test, recv_loop_test, observer_test, service_discovery_test, querent_test, service_server_test, service_info_test).

Key changes per file:
- Replaced `#include "mdnspp/testing/mock_socket_policy.h"` and `mock_timer_policy.h` with `mock_policy.h`
- Replaced `MockSocketPolicy sock; MockTimerPolicy timer;` with `MockSocket sock{mock_executor{}}; MockTimer timer{mock_executor{}};` (or via `MockPolicy` as template argument)
- Replaced all `::create(sock, timer, ...)` factory calls with direct constructors: `observer<MockPolicy>{ex, cb}`
- Removed all `result.has_value()` / `REQUIRE(result.has_value())` checks
- Changed `result->method()` to `value.method()` throughout
- Enqueue test packets via `obj.socket()` after construction, before `start()/discover()/query()`
- In recv_loop_test: replaced `loop.timer().fire()` and `loop.timer().cancel_count()` with local `timer.fire()` and `timer.cancel_count()` (recv_loop no longer exposes `timer()`)
- Added error_code constructor path tests: `MockSocket::set_fail_on_construct(true)` to exercise the `(ex, cb, ec)` constructor
- Added sub-concept static_asserts: `SocketLike<MockSocket>`, `TimerLike<MockTimer>`

**Verification:** 9/9 non-ASIO tests pass.

### Task 2: Migrate ASIO tests, examples, delete old headers, update CMakeLists

**ASIO conformance test** (asio_conformance_test.cpp):
- Replaced `AsioSocketPolicy`/`AsioTimerPolicy` with `AsioSocket`/`AsioTimer`
- Replaced `SocketPolicy<AsioSocketPolicy>` → `Policy<AsioPolicy>` static_asserts
- Added `SocketLike<AsioSocket>` and `TimerLike<AsioTimer>` individual sub-concept asserts
- Updated namespace from `mdnspp::asio_policy::` to `mdnspp::`

**TSAN test** (service_server_tsan_test.cpp):
- Replaced `service_server<AsioSocketPolicy, AsioTimerPolicy>` with `service_server<AsioPolicy>`
- Replaced `::create(sock, timer, timer, info)` with `service_server<AsioPolicy>{io, info}`
- Removed explicit `AsioSocketPolicy`/`AsioTimerPolicy` construction

**Examples** (all 4):
- observe.cpp: `observer<AsioPolicy> obs{io, callback}; obs.start();`
- discover.cpp: `service_discovery<AsioPolicy> sd{io, 3s, callback}; sd.discover(...);`
- query.cpp: `querent<AsioPolicy> q{io, 3s, callback}; q.query(name, qtype);`
- serve.cpp: `service_server<AsioPolicy> srv{io, info, on_query}; srv.start();`

**Deleted 6 legacy headers:**
- `include/mdnspp/socket_policy.h`
- `include/mdnspp/timer_policy.h`
- `include/mdnspp/testing/mock_socket_policy.h`
- `include/mdnspp/testing/mock_timer_policy.h`
- `include/mdnspp/asio/asio_socket_policy.h`
- `include/mdnspp/asio/asio_timer_policy.h`

**CMakeLists.txt:**
- Removed `socket_policy.h`, `timer_policy.h`, `mock_socket_policy.h`, `mock_timer_policy.h` from `PUBLIC_HEADERS`
- Updated testing install to only include `mock_policy.h`
- Updated ASIO install to only include `asio_policy.h`, `asio_socket.h`, `asio_timer.h`
- Updated option description to remove old type names

**service_info.h:** Updated comment from `service_server::create()` to `service_server<P>`

**Verification:** 11/11 tests pass. All 4 examples compile. Zero grep matches for old names.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing] Migrated service_info_test.cpp alongside main test files**
- **Found during:** Task 1
- **Issue:** service_info_test.cpp used `MockSocketPolicy` directly (not in the plan's file list), and would have left a dangling reference to the old type after `mock_socket_policy.h` was deleted
- **Fix:** Migrated service_info_test.cpp to use `MockSocket{mock_executor{}}` and updated test case names accordingly
- **Files modified:** `tests/service_info_test.cpp`
- **Commit:** c902865

## Self-Check: PASSED

- Task 1 commit c902865: FOUND
- Task 2 commit e04c9a2: FOUND
- tests/concept_conformance_test.cpp: FOUND
- 07-03-SUMMARY.md: FOUND
- socket_policy.h deleted: CONFIRMED
- 11/11 tests pass
- Zero old-name references in source tree
