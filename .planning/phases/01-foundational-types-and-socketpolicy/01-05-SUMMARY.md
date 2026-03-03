---
phase: 01-foundational-types-and-socketpolicy
plan: 05
subsystem: api
tags: [cmake, header-guards, always_false, public-headers, requirements, roadmap]

# Dependency graph
requires:
  - phase: 01-foundational-types-and-socketpolicy/01-04
    provides: CMake wiring, concept conformance test, ctest 2/2 passing
provides:
  - service_discovery.h with correct header guard comment
  - socket_policy.h with consolidated detail::always_false (single definition, no redefinition across TUs)
  - CMakeLists.txt PUBLIC_HEADERS without legacy mdns_base.h and record_buffer.h
  - ROADMAP.md Phase 1 with 4 accurate success criteria (AsioSocketPolicy criterion moved to Phase 2)
  - REQUIREMENTS.md TEST-04 split into MockSocketPolicy (Phase 1 complete) and AsioSocketPolicy (Phase 2 pending)
  - REQUIREMENTS.md API-01 annotated with Phase 1 header scope caveat
affects:
  - Phase 2 (AsioSocketPolicy criterion now tracked there as item 6)
  - Phase 3/6 (record_buffer.h/mdns_base.h legacy cleanup still deferred)

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "detail::always_false lives in socket_policy.h — all service headers include socket_policy.h, so one definition satisfies all four class templates"
    - "Header guard comment convention: #endif // HPP_GUARD_MDNSPP_<NAME>_H applied to all service headers"

key-files:
  created: []
  modified:
    - include/mdnspp/socket_policy.h
    - include/mdnspp/service_discovery.h
    - include/mdnspp/querent.h
    - include/mdnspp/service_server.h
    - include/mdnspp/observer.h
    - CMakeLists.txt
    - .planning/ROADMAP.md
    - .planning/REQUIREMENTS.md

key-decisions:
  - "detail::always_false consolidated into socket_policy.h — avoids redefinition ODR violation when all four service headers included in single TU"
  - "mdns_base.h and record_buffer.h removed from PUBLIC_HEADERS/install rules but NOT from disk — internal .cpp files still depend on them; full removal deferred to Phase 3/6"
  - "AsioSocketPolicy success criterion moved from Phase 1 to Phase 2 criterion 6 — Phase 1 only owns MockSocketPolicy verification; AsioSocketPolicy belongs with ARCH-04 in Phase 2"
  - "TEST-04 split in REQUIREMENTS.md into MockSocketPolicy half (Phase 1, complete) and AsioSocketPolicy half (Phase 2, pending) to accurately reflect split delivery"

patterns-established:
  - "Header guard comments: all service headers now use #endif // HPP_GUARD_MDNSPP_<NAME>_H"
  - "Shared detail helpers go in the lowest common include (socket_policy.h) rather than repeated per header"

requirements-completed:
  - API-01
  - ARCH-02
  - TEST-04

# Metrics
duration: 4min
completed: 2026-03-03
---

# Phase 1 Plan 05: Gap Closure Summary

**Header guard comment fixed in service_discovery.h; detail::always_false de-duplicated into socket_policy.h; legacy headers removed from CMakeLists PUBLIC_HEADERS; ROADMAP/REQUIREMENTS scope realigned with deliberate Phase 1 decisions**

## Performance

- **Duration:** 4 min
- **Started:** 2026-03-03T14:13:49Z
- **Completed:** 2026-03-03T14:17:47Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments

- Fixed service_discovery.h bare #endif to #endif // HPP_GUARD_MDNSPP_SERVICE_DISCOVERY_H; matched convention of all other service headers
- Consolidated detail::always_false<T> from four duplicate definitions (service_discovery.h, querent.h, service_server.h, observer.h) into single canonical location in socket_policy.h; all four service headers now compile together in a single TU without ODR violation
- Added #endif // HPP_GUARD_MDNSPP_* comments to querent.h, service_server.h, observer.h, and socket_policy.h (previously all had bare #endif)
- Removed mdns_base.h and record_buffer.h from CMakeLists.txt PUBLIC_HEADERS and install rules; files remain on disk for internal .cpp dependencies
- Moved AsioSocketPolicy success criterion from Phase 1 (criterion 4 of 5) to Phase 2 (criterion 6) in ROADMAP.md; Phase 1 now correctly has 4 criteria
- Split TEST-04 in REQUIREMENTS.md into MockSocketPolicy half (Phase 1, checked complete) and AsioSocketPolicy half (Phase 2, pending); updated traceability table accordingly
- Annotated API-01 in REQUIREMENTS.md with Phase 1 header scope caveat and deferral note for legacy headers

## Task Commits

Each task was committed atomically:

1. **Task 1: Fix service_discovery.h header guard comment** - `2ea2592` (fix)
2. **Task 2: Remove legacy headers from PUBLIC_HEADERS; update ROADMAP and REQUIREMENTS** - `b460465` (fix)

## Files Created/Modified

- `include/mdnspp/socket_policy.h` — Added detail::always_false<T> (single canonical definition); added namespace mdnspp close comment; fixed #endif comment
- `include/mdnspp/service_discovery.h` — Removed duplicate always_false definition; fixed #endif // HPP_GUARD_MDNSPP_SERVICE_DISCOVERY_H
- `include/mdnspp/querent.h` — Removed duplicate always_false definition; fixed #endif // HPP_GUARD_MDNSPP_QUERENT_H
- `include/mdnspp/service_server.h` — Removed duplicate always_false definition; fixed #endif // HPP_GUARD_MDNSPP_SERVICE_SERVER_H
- `include/mdnspp/observer.h` — Removed duplicate always_false definition; fixed #endif // HPP_GUARD_MDNSPP_OBSERVER_H
- `CMakeLists.txt` — Removed mdns_base.h and record_buffer.h from PUBLIC_HEADERS
- `.planning/ROADMAP.md` — Phase 1 success criteria reduced from 5 to 4 (AsioSocketPolicy criterion moved to Phase 2 as criterion 6)
- `.planning/REQUIREMENTS.md` — TEST-04 split into two entries; API-01 scope annotation added; traceability table updated; timestamp updated

## Decisions Made

- Consolidated detail::always_false into socket_policy.h rather than a dedicated detail header — socket_policy.h is already the mandatory include for all four service templates; no additional include needed
- Applied #endif // HPP_GUARD_* fix to all four service headers and socket_policy.h (not just service_discovery.h) because the missing comments were a consistent gap across all of them

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed detail::always_false redefinition ODR violation across all four service headers**
- **Found during:** Task 1 (verifying all four headers compile together)
- **Issue:** detail::always_false was defined identically in service_discovery.h, querent.h, service_server.h, and observer.h; including all four in a single TU caused three "redefinition of struct always_false" errors
- **Fix:** Moved the single canonical definition to socket_policy.h (which all four service headers already include); removed the duplicate definitions from the four service headers
- **Files modified:** include/mdnspp/socket_policy.h, include/mdnspp/service_discovery.h, include/mdnspp/querent.h, include/mdnspp/service_server.h, include/mdnspp/observer.h
- **Verification:** echo '#include ...' | g++ -std=c++23 -Iinclude -fsyntax-only -x c++ - exits 0 with all four headers; MockSocketPolicy concept conformance static_assert still passes
- **Committed in:** 2ea2592 (Task 1 commit)

**2. [Rule 1 - Bug] Fixed bare #endif comments on querent.h, service_server.h, observer.h, socket_policy.h**
- **Found during:** Task 1 (reading the affected headers to remove always_false)
- **Issue:** All three sibling service headers and socket_policy.h had the same bare #endif issue as service_discovery.h; plan only mentioned service_discovery.h but consistency required fixing all
- **Fix:** Added matching #endif // HPP_GUARD_MDNSPP_* comments to all four affected headers
- **Files modified:** include/mdnspp/querent.h, include/mdnspp/service_server.h, include/mdnspp/observer.h, include/mdnspp/socket_policy.h
- **Verification:** grep 'endif' on each file returns the comment-bearing line
- **Committed in:** 2ea2592 (Task 1 commit)

---

**Total deviations:** 2 auto-fixed (both Rule 1 - Bug)
**Impact on plan:** Both fixes were directly triggered by the task's compilation verification step. No scope creep. The always_false consolidation is the canonical fix for the redefinition error; the missing #endif comments on sibling headers were the same class of defect as the one the plan targeted.

## Issues Encountered

None - both deviations were caught by the task's own verification step and fixed inline.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 1 is now fully closed: all three gaps from the verification report are resolved
- Phase 2 (recv_loop and AsioSocketPolicy) can proceed with accurate scope: AsioSocketPolicy criterion is explicitly tracked as Phase 2 criterion 6
- Traceability table in REQUIREMENTS.md accurately reflects which TEST-04 half belongs to which phase
- CMakeLists.txt PUBLIC_HEADERS is clean — only Phase 1 public headers in the install set

---
*Phase: 01-foundational-types-and-socketpolicy*
*Completed: 2026-03-03*
