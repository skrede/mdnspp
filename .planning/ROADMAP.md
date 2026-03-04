# Roadmap: mdnspp

## Overview

v1.0 eliminates all C-library type leakage from the public API and replaces the monolithic `mdns_base` class hierarchy with a flat, policy-based composition. The refactor proceeds in strict dependency order: foundational types and the SocketPolicy concept first (unblocks all testability), then the shared async infrastructure, then the pure-transform parser, then each public type from simplest to most complex. Every public type becomes a class template parameterized on `SocketPolicy`, enabling network-free unit testing via `MockSocketPolicy`. The milestone is complete when all four public types compose from `recv_loop<S>` directly, `mdns_base` is gone, and `discover()` / `query()` return accumulated results via `std::expected`.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3): Planned milestone work
- Decimal phases (2.1, 2.2): Urgent insertions (marked with INSERTED)

Decimal phases appear between their surrounding integers in numeric order.

- [x] **Phase 1: Foundational Types and SocketPolicy** - Define clean record types, mdns_error, and the SocketPolicy concept with MockSocketPolicy; establish the type foundation everything else builds on (completed 2026-03-03)
- [x] **Phase 2: recv_loop and AsioSocketPolicy** - Implement and test the shared async receive infrastructure and production ASIO socket policy (completed 2026-03-03)
- [x] **Phase 3: record_parser Free Functions** - Extract parser as pure byte-span transforms, isolate mdns.h to src/, add parser unit tests (completed 2026-03-03)
- [x] **Phase 4: Refactor service_discovery and querent** - Convert discovery and query types to policy-based templates returning accumulated std::expected results (completed 2026-03-04)
- [ ] **Phase 5: Refactor service_server** - Convert announcement type to policy-based template with strand safety and RFC 6762 timing preserved
- [ ] **Phase 6: Refactor observer** - Convert observer to policy-based template, completing mdns_base elimination and validating perpetual recv_loop path

## Phase Details

### Phase 1: Foundational Types and SocketPolicy
**Goal**: The SocketPolicy concept is defined, MockSocketPolicy satisfies it, and all public record types are clean C++ value types with no mdns.h types visible in include/
**Depends on**: Nothing (first phase)
**Requirements**: API-01, API-02, API-04, ARCH-01, ARCH-02, ARCH-03, BUILD-01, BUILD-03, TEST-04
**Success Criteria** (what must be TRUE):
  1. A header in include/ can be compiled with -DMDNSPP_NO_MDNS_H (or equivalent) without error — no mdns.h type names appear in any public header
  2. `mdns_record_variant` is a `std::variant` of value types; a caller can `std::visit` it without including any C library header
  3. `static_assert(SocketPolicy<MockSocketPolicy>)` compiles in a translation unit that does not link against ASIO
  4. The project builds with `CMAKE_CXX_STANDARD 23` and `CMAKE_CXX_STANDARD_REQUIRED ON` on all three platforms
**Plans**: 5 plans

Plans:
- [x] 01-01-PLAN.md — CMake C++23 upgrade and Catch2 v3.7.1 bump
- [x] 01-02-PLAN.md — Core value type headers: endpoint.h, mdns_error.h, new records.h
- [x] 01-03-PLAN.md — SocketPolicy concept, MockSocketPolicy, and four service template stubs
- [x] 01-04-PLAN.md — CMake wiring, concept conformance test, end-to-end build validation
- [x] 01-05-PLAN.md — Gap closure: service_discovery.h header guard, legacy headers from PUBLIC_HEADERS, ROADMAP/REQUIREMENTS scope alignment

### Phase 2: recv_loop and AsioSocketPolicy
**Goal**: `recv_loop<S, T>` is a standalone tested component that drives the async receive chain; `AsioSocketPolicy` wraps ASIO multicast UDP; both work with mock policies in tests without a real network
**Depends on**: Phase 1
**Requirements**: ARCH-06, ARCH-04, BEHAV-02, BUILD-02, TEST-03
**Success Criteria** (what must be TRUE):
  1. `recv_loop<MockSocketPolicy>` processes a queue of injected packets and delivers them to a callback — verified by a unit test with no real socket
  2. `recv_loop` stop is idempotent: calling `stop()` twice from different threads does not crash or deadlock (verified by ThreadSanitizer)
  3. Silence detection fires the silence callback after no packets for a configured duration, verified with a mock time source
  4. An `asio::io_context` is passed at construction and no executor parameter appears on any public mDNS method
  5. `AsioSocketPolicy` joins the multicast group and starts receiving without blocking the io_context thread (async_receive_from chain, not select())
  6. `static_assert(SocketPolicy<AsioSocketPolicy>)` compiles when ASIO is linked (TEST-04 completion)
**Plans**: 4 plans

Plans:
- [x] 02-01-PLAN.md — TimerPolicy concept and MockTimerPolicy test double (completed 2026-03-03)
- [x] 02-02-PLAN.md — recv_loop internal template and unit tests (completed 2026-03-03)
- [x] 02-03-PLAN.md — CMake ASIO option, AsioSocketPolicy, AsioTimerPolicy (completed 2026-03-03)
- [x] 02-04-PLAN.md — ASIO conformance test and Phase 2 human verification (completed 2026-03-03)

### Phase 3: record_parser Free Functions
**Goal**: All DNS record parsing lives in `mdnspp::parse` free functions that take `std::span<const std::byte>` and return `mdns_record_variant`; mdns.h is confined to src/ and not included from any public header
**Depends on**: Phase 1
**Requirements**: ARCH-07, API-05, TEST-02
**Success Criteria** (what must be TRUE):
  1. A unit test parses PTR, SRV, TXT, A, and AAAA wire bytes into the correct `mdns_record_variant` alternative with no socket or network required
  2. Truncated/malformed input returns a sentinel variant or error rather than undefined behaviour — verified by targeted unit tests
  3. No file in include/ contains `#include <mdns.h>` or references any mdns.h type name
  4. Public API buffer parameters use `std::span<std::byte>` instead of raw pointer/size pairs
**Plans**: 2 plans

Plans:
- [x] 03-01-PLAN.md — Type updates (record_txt entries), record_buffer.h relocation, parse.h/parse.cpp creation, CMake wiring (completed 2026-03-03)
- [x] 03-02-PLAN.md — Parser unit tests (TEST-02) and Phase 3 human verification (completed 2026-03-03)

### Phase 4: Refactor service_discovery and querent
**Goal**: `service_discovery<S>` and `querent<S>` are class templates that compose `recv_loop<S>` directly, return `std::expected<std::vector<mdns_record_variant>, mdns_error>` from their primary methods, and are fully tested via MockSocketPolicy
**Depends on**: Phases 2, 3
**Requirements**: BEHAV-01, API-03, TEST-01
**Success Criteria** (what must be TRUE):
  1. `service_discovery<MockSocketPolicy>::discover()` returns a populated `std::vector<mdns_record_variant>` when the mock socket delivers known DNS wire bytes — no real network required
  2. `querent<MockSocketPolicy>::query()` returns `std::expected<std::vector<mdns_record_variant>, mdns_error>` and the per-record callback is no longer the primary interface
  3. Fallible construction uses a `[[nodiscard]] static std::expected<T, mdns_error> create(...)` factory; throwing constructors are gone for these two types
  4. Neither type inherits from `mdns_base`
**Plans**: 2 plans

Plans:
- [x] 04-01-PLAN.md — DNS wire utilities, service_discovery<S,T> implementation and tests (completed 2026-03-04)
- [x] 04-02-PLAN.md — querent<S,T> implementation, tests, and Phase 4 human verification (completed 2026-03-04)

### Phase 5: Refactor service_server
**Goal**: `service_server<S>` is a class template with strand-serialized shared state, no mutex, and RFC 6762 response timing preserved; tested via MockSocketPolicy
**Depends on**: Phase 4
**Requirements**: BEHAV-03, BEHAV-04
**Success Criteria** (what must be TRUE):
  1. ThreadSanitizer reports no data races in `service_server` after the mutex-to-strand transition commit
  2. A MockSocketPolicy unit test injects a PTR query and verifies the response is sent to the correct endpoint with a 20–500ms delay (simulated via mock timer)
  3. `service_server` does not inherit from `mdns_base`
  4. `std::mutex` is absent from `service_server` source after the dedicated strand-migration commit
**Plans**: 3 plans

Plans:
- [x] 05-01-PLAN.md — service_info type, build_dns_response(), MockSocketPolicy endpoint extension, CMake wiring (completed 2026-03-04)
- [ ] 05-02-PLAN.md — service_server<S,T> template implementation and BDD tests
- [ ] 05-03-PLAN.md — ThreadSanitizer hard-gate test for service_server with AsioSocketPolicy

### Phase 6: Refactor observer
**Goal**: `observer<S>` is a class template composing `recv_loop<S>` for perpetual operation; `mdns_base` is fully deleted from the codebase
**Depends on**: Phase 5
**Requirements**: ARCH-05
**Success Criteria** (what must be TRUE):
  1. `grep -r "mdns_base" include/ src/` returns no matches — the class is gone
  2. `observer<MockSocketPolicy>` receives continuously injected packets and delivers them to a callback until `stop()` is called — verified by unit test
  3. `stop()` on a running observer is idempotent: a second call is a no-op with no crash or assertion failure
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4 → 5 → 6

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Foundational Types and SocketPolicy | 5/5 | Complete   | 2026-03-03 |
| 2. recv_loop and AsioSocketPolicy | 4/4 | Complete   | 2026-03-03 |
| 3. record_parser Free Functions | 2/2 | Complete   | 2026-03-03 |
| 4. Refactor service_discovery and querent | 2/2 | Complete   | 2026-03-04 |
| 5. Refactor service_server | 2/3 | In Progress|  |
| 6. Refactor observer | 0/TBD | Not started | - |
