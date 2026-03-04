---
phase: 11-service-aggregation
plan: 01
subsystem: api
tags: [mdns, rfc6763, aggregation, records, span, ranges, unordered_map]

# Dependency graph
requires:
  - phase: 10-asio-completion-tokens
    provides: async_ public entry-point API; async_initiate overloads
  - phase: 08-native-dns-protocol
    provides: records.h types (record_ptr, record_srv, record_a, record_aaaa, record_txt, mdns_record_variant, service_txt)
provides:
  - resolved_service vocabulary struct (instance_name, hostname, port, txt_entries, ipv4_addresses, ipv6_addresses)
  - aggregate() free function with two-pass RFC 6763 name-chain correlation
  - span<const mdns_record_variant> primary overload plus vector convenience overload
affects: [11-service-aggregation/11-02, async_browse wiring, public API]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Two-pass aggregation: pass 1 builds svc_map + host_to_instances from PTR/SRV/TXT; pass 2 correlates A/AAAA via host_to_instances"
    - "Only PTR records seed resolved_service entries — orphan SRV/A/AAAA are silently ignored"
    - "Deduplication with std::ranges::find for addresses (by value); std::ranges::find_if for TXT (by key, latest wins)"
    - "std::visit with if constexpr type dispatch on mdns_record_variant"

key-files:
  created:
    - include/mdnspp/resolved_service.h
    - tests/service_aggregation_test.cpp
  modified:
    - tests/CMakeLists.txt

key-decisions:
  - "resolved_service has no TTL field — plain aggregate value type, not a cache entry"
  - "aggregate() implemented inline in header — small function, logically belongs with the type it produces"
  - "span<const mdns_record_variant> is the canonical overload; vector overload delegates to it"
  - "SRV latest-wins for hostname/port — both host_to_instances and svc_map updated on each SRV for same instance name"

patterns-established:
  - "resolved_service pattern: plain aggregate struct with vector fields, no methods — follows service_info.h"
  - "Two-pass address correlation ensures arrival-order independence for A/AAAA vs SRV"

requirements-completed: [AGG-01, AGG-02, AGG-04]

# Metrics
duration: ~10min
completed: 2026-03-04
---

# Phase 11 Plan 01: Service Aggregation Summary

**resolved_service struct and aggregate() free function implementing RFC 6763 two-pass PTR->SRV->TXT->A/AAAA name-chain correlation with deduplication and PTR-only seeding**

## Performance

- **Duration:** ~10 min
- **Started:** 2026-03-04
- **Completed:** 2026-03-04
- **Tasks:** 1 (TDD: tests + implementation in single commit)
- **Files modified:** 3

## Accomplishments

- Defined `resolved_service` vocabulary struct with all six required fields
- Implemented `aggregate()` with two-pass algorithm ensuring A/AAAA arriving before SRV are still correlated
- Full deduplication: IP addresses by value, TXT entries by key (latest wins), SRV latest wins
- 18 test cases covering all specified behaviors (81 assertions, all pass)

## Task Commits

Each task was committed atomically:

1. **Task 1: Define resolved_service struct and aggregate() function with TDD** - `f461d26` (feat)

**Plan metadata:** (docs commit follows)

_Note: TDD task implemented with RED phase (tests written first) and GREEN phase (implementation to pass tests) in single commit as plan specifies write-tests-then-implementation workflow._

## Files Created/Modified

- `include/mdnspp/resolved_service.h` — resolved_service struct and aggregate() inline implementation
- `tests/service_aggregation_test.cpp` — 18 pure unit tests, no mock policy, no networking
- `tests/CMakeLists.txt` — added `make_test(service_aggregation_test)` line

## Decisions Made

- No TTL field on resolved_service — it is a plain value type, not a cache entry (locked decision from plan)
- aggregate() inline in header — small function, logically belongs with the type it produces
- span overload is primary, vector overload delegates — avoids duplication, idiomatic C++23
- SRV latest-wins: both `hostname`/`port` on the entry AND `host_to_instances` mapping are updated when a second SRV for the same instance arrives

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- `resolved_service.h` is ready for Plan 02 to wire into `async_browse` result delivery
- `aggregate()` is a pure function — can be called anywhere records accumulate without coupling to networking or executor
- Test patterns established for Plan 02 integration tests

---
*Phase: 11-service-aggregation*
*Completed: 2026-03-04*
