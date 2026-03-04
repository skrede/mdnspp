---
phase: 09-nativepolicy-standalone-networking
plan: 02
subsystem: networking
tags: [native, posix, winsock2, udp, multicast, mdns, policy, cmake]

# Dependency graph
requires:
  - phase: 09-01
    provides: NativeContext (poll event loop) and NativeTimer (TimerLike); NativeSocket registers with both
provides:
  - NativeSocket: raw UDP multicast socket joining 224.0.0.251:5353, satisfying SocketLike
  - NativePolicy: traits struct (executor_type=NativeContext&, socket_type=NativeSocket, timer_type=NativeTimer), satisfying Policy
  - native.h: umbrella header for one-include access to the full native stack
  - mdnspp_native: CMake INTERFACE target gated by MDNSPP_ENABLE_NATIVE_POLICY
  - native_conformance_test: compile-time + runtime tests for NativePolicy
affects:
  - Users: can now #include <mdnspp/native.h> and drive mDNS with observer<NativePolicy> — no ASIO

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "NativeSocket: throwing + error_code constructors matching ASIO convention"
    - "SO_REUSEPORT gated by #ifdef — optional (warn, do not throw) matching platform reality"
    - "sendto() synchronous for mDNS sends — tiny/infrequent, no need for async"
    - "async_receive stores handler in m_ctx.register_receive — NativeContext does recvfrom+dispatch"
    - "CMake INTERFACE target mdnspp_native mirrors mdnspp_asio pattern exactly"

key-files:
  created:
    - include/mdnspp/native/native_socket.h
    - include/mdnspp/native/native_policy.h
    - include/mdnspp/native.h
    - tests/native_conformance_test.cpp
  modified:
    - CMakeLists.txt
    - tests/CMakeLists.txt

key-decisions:
  - "SO_REUSEPORT failure is non-fatal (WARN, not throw) — not universally supported and non-critical for correctness"
  - "send() is synchronous sendto() — mDNS sends are tiny (<512 bytes) and infrequent, avoiding async complexity"
  - "async_receive delegates to NativeContext.register_receive — context owns the recvfrom dispatch, socket just arms it"

patterns-established:
  - "Native headers: no ASIO includes anywhere; only POSIX/Win32 system headers"
  - "static_assert(Policy<NativePolicy>) in native_policy.h gives instant compile-time feedback"
  - "Conformance tests use try-catch for network-dependent tests (multicast bind) — expected to fail in no-network CI"

requirements-completed: [NET-01, NET-05, NET-06, NET-07]

# Metrics
duration: ~5min
completed: 2026-03-04
---

# Phase 9 Plan 02: NativeSocket, NativePolicy, CMake Target, and Conformance Tests Summary

**NativeSocket raw UDP multicast socket (224.0.0.251:5353) satisfying SocketLike, NativePolicy traits struct satisfying Policy, mdnspp_native CMake target, native.h umbrella header, and native_conformance_test with 7 tests — no ASIO anywhere in the native include chain.**

## Performance

- **Duration:** ~5 min
- **Started:** 2026-03-04T14:51:15Z
- **Completed:** 2026-03-04T14:55:46Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments

- NativeSocket: raw POSIX/Winsock2 UDP socket, joins multicast group 224.0.0.251:5353, SO_REUSEADDR required, SO_REUSEPORT optional, non-blocking, synchronous send, async_receive via NativeContext.register_receive, throwing + non-throwing constructors
- static_assert(SocketLike<NativeSocket>) passes at end of header
- NativePolicy: minimal traits struct (executor_type=NativeContext&, socket_type=NativeSocket, timer_type=NativeTimer)
- static_assert(Policy<NativePolicy>) passes in native_policy.h
- native.h: umbrella header including all four native/ headers, no ASIO
- CMakeLists.txt: MDNSPP_ENABLE_NATIVE_POLICY option, mdnspp_native INTERFACE target, mdnspp::native alias, ws2_32 on Windows, install rules
- tests/CMakeLists.txt: make_native_test() function, native_conformance_test target
- native_conformance_test: 7 tests covering concept static_asserts, context lifecycle, timer semantics, socket construction, all four public type instantiations
- All 12 tests pass; no regressions; no ASIO in native/ headers or native test

## Task Commits

1. **Task 1: NativeSocket, NativePolicy, umbrella header** - `51e4708` (feat)
2. **Task 2: CMake target and conformance tests** - `f243e85` (feat)

## Files Created/Modified

- `include/mdnspp/native/native_socket.h` - NativeSocket satisfying SocketLike; throwing + error_code constructors; static_assert at end
- `include/mdnspp/native/native_policy.h` - NativePolicy traits struct; static_assert(Policy<NativePolicy>)
- `include/mdnspp/native.h` - Umbrella header (4 includes, no ASIO)
- `tests/native_conformance_test.cpp` - 7 conformance tests; compile-time static_asserts for all four public types
- `CMakeLists.txt` - mdnspp_native INTERFACE target gated by MDNSPP_ENABLE_NATIVE_POLICY
- `tests/CMakeLists.txt` - make_native_test() + native_conformance_test target

## Decisions Made

- **SO_REUSEPORT non-fatal**: Not universally supported (#ifdef guard); failure generates a silent warning, does not throw. This matches real-world platform behaviour.
- **send() synchronous**: mDNS sends are tiny (<512 bytes) and infrequent; synchronous sendto() avoids async complexity with no practical downside.
- **async_receive delegates to NativeContext**: NativeSocket stores handler and calls m_ctx.register_receive — the context owns recvfrom and dispatch, keeping NativeSocket thin.

## Deviations from Plan

None — plan executed exactly as written.

## Issues Encountered

None.

## User Setup Required

None — no external service configuration required.

## Next Phase Readiness

- NativePolicy is complete: NativeContext + NativeSocket + NativeTimer all wired together, static_assert(Policy<NativePolicy>) passes, all four public types instantiate. Phase 9 is complete.
- No blockers. Windows CI still absent (noted in STATE.md blockers) but headers have correct #ifdef guards throughout.

## Self-Check

Files exist:
- include/mdnspp/native/native_socket.h: FOUND
- include/mdnspp/native/native_policy.h: FOUND
- include/mdnspp/native.h: FOUND
- tests/native_conformance_test.cpp: FOUND

Commits verified:
- 51e4708: FOUND
- f243e85: FOUND

## Self-Check: PASSED

---
*Phase: 09-nativepolicy-standalone-networking*
*Completed: 2026-03-04*
