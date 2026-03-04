# Roadmap: mdnspp

## Milestones

- **v1.0 Clean API & Architecture** — Phases 1-6 (shipped 2026-03-04) | [archive](milestones/v1.0-ROADMAP.md)
- **v2.0 Standalone & Ergonomic** — Phases 7-11 (in progress)

## Phases

<details>
<summary>v1.0 Clean API & Architecture (Phases 1-6) — SHIPPED 2026-03-04</summary>

- [x] Phase 1: Foundational Types and SocketPolicy (5/5 plans) — completed 2026-03-03
- [x] Phase 2: recv_loop and AsioSocketPolicy (4/4 plans) — completed 2026-03-03
- [x] Phase 3: record_parser Free Functions (2/2 plans) — completed 2026-03-03
- [x] Phase 4: Refactor service_discovery and querent (2/2 plans) — completed 2026-03-04
- [x] Phase 5: Refactor service_server (3/3 plans) — completed 2026-03-04
- [x] Phase 6: Refactor observer (2/2 plans) — completed 2026-03-04

</details>

### v2.0 Standalone & Ergonomic (In Progress)

**Milestone Goal:** Make mdnspp truly standalone (no C library, optional ASIO) with an ergonomic single-policy API using ASIO completion token patterns.

- [x] **Phase 7: Policy Unification and Direct Construction** - Merge dual policies into one `Policy` concept; direct constructors with throw/error_code; `MockPolicy` unified test double (completed 2026-03-04)
- [x] **Phase 8: Native DNS Protocol** - Replace mjansson/mdns C library with a pure C++ RFC 1035-compliant decoder; remove all C library dependencies from the build (completed 2026-03-04)
- [ ] **Phase 9: NativePolicy Standalone Networking** - Raw UDP multicast socket policy with `run()`/`poll()` event loop; no ASIO in include chain; cross-platform
- [ ] **Phase 10: ASIO Completion Tokens** - Wire `async_initiate` across all four public types; support callback, `use_future`, `use_awaitable`, and `deferred` from one call site
- [ ] **Phase 11: Service Aggregation** - `resolved_service` struct correlating PTR+SRV+TXT+A/AAAA records; `async_discover` returns aggregated results in one completion

## Phase Details

### Phase 7: Policy Unification and Direct Construction
**Goal**: All four public types use a single `Policy` template parameter, are directly constructible, and the full test suite passes with `MockPolicy`
**Depends on**: Phase 6 (v1.0 complete)
**Requirements**: API-01, API-02, API-03, API-04, API-05, API-06, API-07, API-08
**Success Criteria** (what must be TRUE):
  1. `observer<AsioPolicy>(io, cb)` compiles and runs — no `create()` call, no `SocketPolicy`/`TimerPolicy` split
  2. A constructor failure (bad socket) throws `std::system_error` by default; the `(io, cb, ec)` overload sets `ec` instead
  3. `static_assert(Policy<MockPolicy>)` passes and all existing unit tests compile against the unified `MockPolicy`
  4. `recv_loop<P>` uses a single policy type parameter; `recv_loop<S,T>` alias is gone
  5. `create()` factory is absent from all four public types — any call site using it fails to compile
**Plans**: 3 plans
  - [ ] 07-01-PLAN.md — Define Policy concept layer and concrete policy types (MockPolicy, AsioPolicy)
  - [ ] 07-02-PLAN.md — Migrate recv_loop and public types to single Policy parameter with direct constructors
  - [ ] 07-03-PLAN.md — Migrate tests/examples to unified API and delete old headers

### Phase 8: Native DNS Protocol
**Goal**: mjansson/mdns is fully removed; all record parsing is performed by native C++ code that is RFC 1035-compliant and safe against crafted packets
**Depends on**: Phase 7
**Requirements**: PROTO-01, PROTO-02, PROTO-03, PROTO-04, PROTO-05
**Success Criteria** (what must be TRUE):
  1. CMakeLists.txt contains no `FetchContent_Declare(mdns ...)` block and no `target_link_libraries(... mdns)` line
  2. `read_dns_name` correctly decompresses a self-referential pointer (`{0xC0, 0x0C}` at offset 12) without looping — returns an error
  3. PTR, SRV, TXT, A, and AAAA records parse identically to the previous mjansson-backed implementation — all existing record parser tests pass with no behavioral changes
  4. No `<mdns.h>` include appears anywhere in `src/` or `include/`
**Plans**: 2 plans
  - [x] 08-01-PLAN.md — TDD: Implement read_dns_name in dns_wire.h with RFC 1035/9267 safety tests
  - [x] 08-02-PLAN.md — Replace mjansson calls in parse.cpp, clean mdns_util, remove C library from build

### Phase 9: NativePolicy Standalone Networking
**Goal**: Users can drive mdnspp service discovery and announcement using only OS sockets — no ASIO header in the include chain
**Depends on**: Phase 7, Phase 8
**Requirements**: NET-01, NET-02, NET-03, NET-04, NET-05, NET-06, NET-07
**Success Criteria** (what must be TRUE):
  1. `observer<NativePolicy>(native, cb)` compiles and receives mDNS traffic on a live network without any ASIO include
  2. `NativePolicy::run()` blocks and processes I/O until `stop()` is called; `poll_one()` returns immediately when no I/O is ready
  3. IPv4 multicast group `224.0.0.251:5353` is joined on Linux, macOS, and Windows without silent failure (`SO_REUSEPORT` guarded, bind uses `INADDR_ANY`)
  4. All four public types (`observer`, `service_discovery`, `querent`, `service_server`) instantiate and function with `NativePolicy`
**Plans**: TBD

### Phase 10: ASIO Completion Tokens
**Goal**: Every async operation on all four public types accepts any ASIO completion token — callback, future, coroutine, and deferred — from a single function call
**Depends on**: Phase 7
**Requirements**: API-09, API-10, API-11, API-12, API-13
**Success Criteria** (what must be TRUE):
  1. `async_discover(asio::use_future)` returns a `std::future<T>` that the caller can `.get()` after `io.run()`
  2. `co_await async_observe(asio::use_awaitable)` compiles and suspends correctly in a C++23 coroutine context
  3. Completion handlers are dispatched on the handler's associated executor — TSan reports no data races on a two-thread `io_context`
  4. `async_discover(asio::deferred)` produces a composable operation that does not initiate I/O until it is launched
**Plans**: TBD

### Phase 11: Service Aggregation
**Goal**: Callers receive a single `resolved_service` value per discovered service rather than a stream of raw record variants
**Depends on**: Phase 10
**Requirements**: AGG-01, AGG-02, AGG-03, AGG-04
**Success Criteria** (what must be TRUE):
  1. `resolved_service` contains service name, hostname, port, TXT key-value pairs, and all resolved IP addresses (IPv4 and IPv6)
  2. `async_discover` delivers one `resolved_service` per service at silence timeout — PTR, SRV, TXT, and address records are correlated by name
  3. A service discovered with only a PTR record (no SRV/TXT yet) is tracked internally and completed when remaining records arrive — no premature delivery
  4. The existing flat `results()` accessor continues to work — service aggregation is additive, not a replacement
**Plans**: TBD

## Progress

**Execution Order:** 7 → 8 → 9 → 10 → 11

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Foundational Types and SocketPolicy | v1.0 | 5/5 | Complete | 2026-03-03 |
| 2. recv_loop and AsioSocketPolicy | v1.0 | 4/4 | Complete | 2026-03-03 |
| 3. record_parser Free Functions | v1.0 | 2/2 | Complete | 2026-03-03 |
| 4. Refactor service_discovery and querent | v1.0 | 2/2 | Complete | 2026-03-04 |
| 5. Refactor service_server | v1.0 | 3/3 | Complete | 2026-03-04 |
| 6. Refactor observer | v1.0 | 2/2 | Complete | 2026-03-04 |
| 7. Policy Unification and Direct Construction | 3/3 | Complete   | 2026-03-04 | - |
| 8. Native DNS Protocol | v2.0 | 2/2 | Complete | 2026-03-04 |
| 9. NativePolicy Standalone Networking | v2.0 | 0/? | Not started | - |
| 10. ASIO Completion Tokens | v2.0 | 0/? | Not started | - |
| 11. Service Aggregation | v2.0 | 0/? | Not started | - |
