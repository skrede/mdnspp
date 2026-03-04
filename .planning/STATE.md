---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
status: unknown
last_updated: "2026-03-04T04:39:33.806Z"
progress:
  total_phases: 5
  completed_phases: 5
  total_plans: 16
  completed_plans: 16
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-03)

**Core value:** A C++23 mDNS library that composes naturally with any executor or event loop — no owned threads, no hidden allocations, no C types leaking into user code.
**Current focus:** Phase 5 Plan 03 COMPLETE — TSan hard-gate test for service_server<AsioSocketPolicy, AsioTimerPolicy>, TSan clean run verified, Phase 5 fully complete; ready for Phase 6 (ASIO wiring)

## Current Position

Phase: 5 of 5 (refactor-service-server) — COMPLETE
Plan: 3 of 3 in phase — COMPLETE
Status: Plan 05-03 complete — TSan test (2 SCENARIO blocks, cross-thread stop + double-stop), ASIO build passes (10/10 tests), TSan build clean (no data races), Phase 5 DONE
Last activity: 2026-03-04 — Completed 05-03 (TSan hard-gate test, fixed non-copyable ASIO type handling in service_server, recv_loop::socket() accessor added)

Progress: [████████████████████] 100% (All 5 phases complete)

## Performance Metrics

**Velocity:**
- Total plans completed: 13
- Average duration: 3.4 min
- Total execution time: 0.24 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 01-foundational-types-and-socketpolicy | 4 | 15 min | 3.7 min |
| 02-recv-loop-and-asio-socket-policy | 4 | 13 min | 3.2 min |
| 03-record-parser-free-functions | 2 | 17 min | 8.5 min |
| 04-refactor-service-discovery-and-querent | 2 | 10 min | 5.0 min |
| 05-refactor-service-server | 3 | 16 min | 5.3 min |

**Recent Trend:**
- Last 5 plans: 04-01 (6 min), 04-02 (4 min), 05-01 (5 min), 05-02 (3 min), 05-03 (8 min)
- Trend: stable

*Updated after each plan completion*
| Phase 05-refactor-service-server P02 | 3 | 2 tasks | 2 files |
| Phase 05-refactor-service-server P03 | 8 | 1 tasks | 5 files |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- Incremental evolution, not rewrite — clean API surface delivers value faster than waiting for full reimplementation
- Policy-based over CRTP/virtual hierarchy — enables network-free unit testing via MockSocket
- Constructor injection for executor — keeps mDNS public API clean; user wires once
- std::expected for error handling — C++23 native; no exceptions; explicit error paths
- Keep mdns.h short-term — RFC compliance is non-trivial; maintain correctness while evolving
- [01-01] CMAKE_CXX_EXTENSIONS OFF mandatory — prevents GCC from using -std=gnu++23 instead of -std=c++23
- [01-01] CMAKE_CXX_STANDARD_REQUIRED ON — build fails loudly if compiler lacks C++23 support
- Record type identity from variant alternative (no rtype/etype tag fields) — caller uses std::visit
- record_a/record_aaaa expose std::string address_string only — sockaddr_in/sockaddr_in6 dropped
- mdns_error is flat enum class — std::error_code category integration deferred to Phase 4+
- [01-03] SocketPolicy concept uses std::function handler type (not lambda) to avoid unique closure-type constraint failures
- [01-03] MockSocketPolicy lives in mdnspp::testing; async_receive synchronously drains queue — deterministic, no threads
- [01-03] detail::always_false<T> dependent-false pattern used in all four service template stubs — IFNDR-safe in C++23
- [01-04] legacy_records.h created in src/mdnspp/ (private) as transitional bridge for internal .cpp files still using old C-based record types — Phase 3/6 cleanup target
- [01-04] record_parser.h moved from public include/ to private src/ — it only uses internal types and is not a public API surface
- [01-05] detail::always_false consolidated into socket_policy.h — avoids ODR redefinition when all four service headers included in single TU; socket_policy.h is the mandatory shared include
- [01-05] mdns_base.h and record_buffer.h removed from CMakeLists.txt PUBLIC_HEADERS/install rules — files remain on disk for internal .cpp dependencies; full removal deferred to Phase 3/6
- [01-05] AsioSocketPolicy success criterion moved from Phase 1 to Phase 2 criterion 6 — MockSocketPolicy is Phase 1; AsioSocketPolicy belongs with ARCH-04 in Phase 2
- [01-05] Header guard comment convention: all service headers and socket_policy.h use #endif // HPP_GUARD_MDNSPP_<NAME>_H
- [02-01] TimerPolicy concept uses no return constraint on expires_after — asio::steady_timer returns std::size_t; constraining to void would break AsioTimerPolicy
- [02-01] expires_after() in MockTimerPolicy clears pending handler and increments cancel_count — simulates asio cancel-and-reschedule semantics
- [02-01] static_assert(TimerPolicy<MockTimerPolicy>) placed at global scope in mock_timer_policy.h — conformance checked at every include site
- [02-02] recv_loop constructor takes S and T by value (moved in) — no executor parameter on any public method; executor hidden inside policy (BEHAV-02)
- [02-02] recv_loop is non-copyable and non-movable — lambda callbacks capture this by pointer; moving after start() would invalidate captures
- [02-02] pop-before-handler in MockSocketPolicy: copy packet out, pop queue, then call handler — prevents infinite recursion when arm_receive() recurses from synchronous callbacks
- [02-02] make_asio_test() CMake helper added in plan 02-02 to avoid file collision with plan 02-03 (same wave, both would own tests/CMakeLists.txt)
- [02-03] asio::ip::make_address() used — from_string() removed in ASIO 1.36.0; plan template used deprecated API
- [02-03] Bind to INADDR_ANY:5353 then join_group(224.0.0.251) — Linux/macOS pattern; binding to multicast address itself breaks Linux reception
- [02-03] AsioSocketPolicy close() defers strand wiring to Phase 5 (BEHAV-03) — current implementation calls cancel(ec)/close(ec) ignoring errors
- [02-03] ASIO_STANDALONE propagated via mdnspp_asio INTERFACE cmake target — no manual #define in headers
- [02-04] TU-scope static_asserts alongside header-scope ones — explicit TEST-04 documentation; reader sees intent without inspecting headers
- [02-04] Runtime AsioSocketPolicy test uses try/catch with WARN — multicast bind failure in sandboxed CI must not block the phase gate
- [02-04] Phase 2 human-verify checkpoint confirmed all 6 ROADMAP success criteria (4 suites, 26 assertions across both builds)
- [03-01] record_metadata.rtype is uint16_t (not enum) — avoids maintaining parallel enum alongside mdns_record_type; raw integer constants (1=A, 12=PTR, 16=TXT, 28=AAAA, 33=SRV) used in switch
- [03-01] Empty TXT record (count==0) returns valid record_txt with empty entries vector — RFC 6763 compliant; only bounds violations return error
- [03-01] record_buffer.h include paths left unchanged after move to src/ — "mdnspp/record_buffer.h" resolves to src/mdnspp/record_buffer.h via PRIVATE src/ include directory; no changes needed in mdns_base.h, record_parser.h, or record_buffer.cpp
- [03-01] mdns_string_extract called in all 5 per-type functions (not just PTR/SRV) to consistently populate the name field for all record types
- [03-02] All Phase 3 deliverables front-loaded into 03-01; 03-02 is verification-only — parse_test.cpp 17 scenarios, all 4 Phase 3 ROADMAP success criteria confirmed passing
- [Phase 04-01]: socket() test accessor added to service_discovery to enable sent_packets inspection (mirrors recv_loop::timer() pattern)
- [Phase 04-01]: recv_loop constructed with copies in discover() — non-copyable/non-movable constraint satisfied, enables multiple discover() calls
- [Phase 04-01]: Empty-queue silence-timeout test skipped in service_discovery_test — MockTimerPolicy::fire() inaccessible from outside discover(); covered by recv_loop_test.cpp
- [Phase 04-02]: query() signature is query(std::string_view name, uint16_t qtype) — flat DNS-idiomatic parameters; caller specifies QNAME and QTYPE directly
- [Phase 04-02]: recv_loop constructed with copies of m_socket and m_timer inside query() — same pattern as discover(); allows multiple query() calls per querent instance
- [Phase 04-02]: socket() test accessor added to querent — needed to inspect sent_packets from m_socket internal copy; mirrors service_discovery::socket() pattern
- [Phase 05-01]: response_detail namespace used for build_dns_response internal helpers — keeps them scoped without polluting mdnspp::detail
- [Phase 05-01]: MockSocketPolicy queue changed from queue<vector<byte>> to queue<pair<vector<byte>, endpoint>> — stores sender for endpoint-aware delivery; backward compat via enqueue(packet) calling enqueue(packet, endpoint{})
- [Phase 05-01]: build_dns_response returns empty vector for A/AAAA when no address available — caller checks before sending
- [Phase 05-01]: qtype=255 (ANY) produces all available records as answers (not additional) — simplifies ANY response assembly
- [Phase 05-02]: service_server dual-timer ownership: two separate timer instances passed to create() — independent timer lifecycles without shared state
- [Phase 05-02]: recv_loop silence timeout = 24*365h in service_server — run-until-stop semantics, avoids restart complexity
- [Phase 05-refactor-service-server]: service_server::create() now takes two separate timer parameters (response_timer, recv_timer) — AsioTimerPolicy wraps asio::steady_timer which is non-copyable
- [Phase 05-refactor-service-server]: service_server::start() moves m_socket and m_recv_timer into recv_loop (not copy) — socket() accessor delegates to m_loop->socket() after start()
- [Phase 05-refactor-service-server]: recv_loop::socket() accessor added to support service_server send path after m_socket is moved into recv_loop on start()

### Pending Todos

None yet.

### Blockers/Concerns

- Research flag: Multicast join platform behavior (macOS, Windows) warrants empirical validation before Phase 2 plan is finalized
- Research flag: mdns C library fork compatibility with -std=c++23 should be verified early in Phase 1
- legacy_records.h bridge for Phase 3/6 migration (record_builder and record_parser still use old C-based record types)

## Session Continuity

Last session: 2026-03-04
Stopped at: Completed 05-03-PLAN.md (TSan hard-gate test, service_server non-copyable ASIO fix, TSan clean run, Phase 5 COMPLETE)
Resume file: None
