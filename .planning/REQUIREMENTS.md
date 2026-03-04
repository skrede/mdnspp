# Requirements: mdnspp

**Defined:** 2026-03-03
**Core Value:** A C++23 mDNS library that composes naturally with any executor or event loop — no owned threads, no hidden allocations, no C types leaking into user code.

## v1.0 Requirements

Requirements for milestone v1.0: Clean API & Architecture.

### API — Public Type Surface

- [x] **API-01** (Phase 1 headers): Public headers expose no mdns.h types — all new Phase 1 headers (endpoint.h, mdns_error.h, records.h, socket_policy.h, mock_socket_policy.h, and four service template stubs) are clean. Legacy headers `mdns_base.h` (Phase 6) and `record_buffer.h` (Phase 3/6) remain in `include/` but are removed from PUBLIC_HEADERS and install rules; full cleanup is deferred per CONTEXT.md.
- [x] **API-02**: Record types are `std::variant` value types (`mdns_record_variant = std::variant<record_ptr, record_srv, record_a, record_aaaa, record_txt>`; callers use `std::visit`; no `shared_ptr` in public API)
- [x] **API-03**: Fallible construction uses `std::expected` factory functions (`static std::expected<T, mdns_error> create(...)` replaces throwing constructors; `[[nodiscard]]` enforced)
- [x] **API-04**: `mdns_error` enum class replaces `std::runtime_error` (library-specific error category with meaningful codes; used as the `E` in all `std::expected<T, mdns_error>` return types)
- [x] **API-05**: Buffer API uses `std::span<std::byte>` (caller-owned buffers; no raw pointer/size pairs in public API)

### Architecture — Policy-Based Composition

- [x] **ARCH-01**: `SocketPolicy` concept defined using only standard library vocabulary (`std::error_code`, `std::span<std::byte>`; no ASIO types in concept definition; `static_assert` verified)
- [x] **ARCH-02**: All four public types are class templates parameterized on `SocketPolicy` (`service_discovery<S>`, `service_server<S>`, `querent<S>`, `observer<S>`)
- [x] **ARCH-03**: `MockSocketPolicy` satisfies the `SocketPolicy` concept (hand-written test double with injected packet queue; `static_assert(SocketPolicy<MockSocketPolicy>)` in a translation unit that does not link against ASIO)
- [x] **ARCH-04**: `AsioSocketPolicy` provides production async I/O (standalone ASIO 1.30.x; `asio::ip::udp::socket`; multicast join sequence; `async_receive_from` chain; `ASIO_STANDALONE` defined; no Boost dependency)
- [x] **ARCH-05**: `mdns_base` removed — flat composition replaces inheritance (`recv_loop<S>` is a member, not a base; each public type composes socket + recv_loop directly; no shared base class)
- [x] **ARCH-06**: `recv_loop<S>` implemented as a standalone internal component (owns receive buffer as `std::vector<std::byte>`; passes `std::span<std::byte>` to policy; silence detection via `asio::steady_timer`; stop is idempotent)
- [x] **ARCH-07**: `record_parser` implemented as free functions in `mdnspp::parse` namespace (`std::span<const std::byte>` + endpoint → `mdns_record_variant`; `mdns.h` confined to `src/`; testable without sockets)

### Behavior — Runtime Semantics

- [x] **BEHAV-01**: `discover()` and `query()` return accumulated results (`std::expected<std::vector<mdns_record_variant>, mdns_error>`; per-record callback removed as primary interface)
- [x] **BEHAV-02**: Executor injected at construction and hidden from public mDNS methods (user passes `asio::any_io_executor` or `asio::io_context&` once at construction; `announce()`, `discover()`, `query()`, `observe()` have no executor parameters)
- [x] **BEHAV-03**: `asio::strand` replaces `std::mutex` in `service_server` (all shared state access serialised through strand; mutex removed only after ThreadSanitizer clean run in a dedicated isolated commit)
- [x] **BEHAV-04**: RFC 6762 response timing preserved in `service_server` (20–500ms random delay before multicast responses; timing logic maintained through strand-based dispatch)

### Testing — Unit Coverage

- [x] **TEST-01**: Unit tests for all four operation types via `MockSocketPolicy` (inject known DNS wire bytes, verify accumulated results; no real network required)
- [x] **TEST-02**: `record_parser` unit tests with raw byte spans (PTR, SRV, TXT, A, AAAA records; edge cases: truncated names, unknown record types, TXT key-value parsing)
- [x] **TEST-03**: `recv_loop` unit tests (async receive chain, stop idempotency, silence detection, mock packet injection and delivery)
- [x] **TEST-04** (MockSocketPolicy — Phase 1): `static_assert(SocketPolicy<MockSocketPolicy>)` in a TU that does not link against ASIO — verified in Phase 1
- [x] **TEST-04** (AsioSocketPolicy — Phase 2): `static_assert(SocketPolicy<AsioSocketPolicy>)` in a TU that links against ASIO — verified in Phase 2 plan 02-04 (asio_conformance_test.cpp)

### Build — C++23 Upgrade

- [x] **BUILD-01**: CMake configured for C++23 (`CMAKE_CXX_STANDARD 23`, `CMAKE_CXX_STANDARD_REQUIRED ON`, `CMAKE_CXX_EXTENSIONS OFF`; CMake minimum version 3.25)
- [x] **BUILD-02**: Standalone ASIO added as optional FetchContent dependency (`MDNSPP_ENABLE_ASIO_POLICY=ON` CMake option; `ASIO_STANDALONE` defined on all targets that include ASIO headers; fetched only when enabled)
- [x] **BUILD-03**: Catch2 updated to 3.7.x (bump from 3.3.2; verify latest tag at https://github.com/catchorg/Catch2/releases; no API changes required)

## Future Requirements

Deferred to a subsequent milestone. Not in the current roadmap.

### Allocators

- **ALLOC-01**: Custom allocator support via PMR (`std::pmr` containers in record accumulation; `std::pmr::memory_resource` parameter on public types)
- **ALLOC-02**: Allocator-aware `record_variant` types (no heap allocation in steady-state for middleware use case)

### Async Ergonomics

- **ASYNC-01**: Coroutine awaitable API (`co_await discover()` returning `std::expected<std::vector<mdns_record_variant>, mdns_error>`; requires stable AsioSocketPolicy)
- **ASYNC-02**: Structured service aggregation (single `service_record` combining PTR+SRV+TXT+A/AAAA; user-visible convenience type)

### Internals

- **INTERN-01**: Full elimination of mdns.h dependency (native C++ DNS wire format parser replaces C library; mdns.h no longer fetched)
- **INTERN-02**: RFC 6762 conflict resolution (service name uniqueness probing; persistence on network re-join)

## Out of Scope

Explicitly excluded. Documented to prevent scope creep.

| Feature | Reason |
|---------|--------|
| Full DNS resolver | Different protocol, different scope — mDNS only |
| ROS2 integration | Middleware is a separate project; mdnspp exposes interfaces, middleware integrates |
| Mobile platforms (iOS/Android) | Not a current target |
| mDNS-SD extensions beyond RFC 6762/6763 | Stay RFC-compliant; no proprietary extensions |
| Boost.ASIO | Standalone ASIO only (non-Boost); Boost is not an acceptable dependency |
| Exception-based error handling | std::expected is the chosen model; no mixed exception/expected API |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| API-01 | Phase 1 | Complete |
| API-02 | Phase 1 | Complete |
| API-04 | Phase 1 | Complete |
| ARCH-01 | Phase 1 | Complete |
| ARCH-02 | Phase 1 | Complete |
| ARCH-03 | Phase 1 | Complete |
| BUILD-01 | Phase 1 | Complete |
| BUILD-03 | Phase 1 | Complete |
| TEST-04 (MockSocketPolicy) | Phase 1 | Complete |
| TEST-04 (AsioSocketPolicy) | Phase 2 | Complete |
| ARCH-06 | Phase 2 | Complete |
| ARCH-04 | Phase 2 | Complete |
| BEHAV-02 | Phase 2 | Complete |
| BUILD-02 | Phase 2 | Complete |
| TEST-03 | Phase 2 | Complete |
| ARCH-07 | Phase 3 | Complete |
| API-05 | Phase 3 | Complete |
| TEST-02 | Phase 3 | Complete |
| BEHAV-01 | Phase 4 | Complete |
| API-03 | Phase 4 | Complete |
| TEST-01 | Phase 4 | Complete |
| BEHAV-03 | Phase 5 | Complete |
| BEHAV-04 | Phase 5 | Complete |
| ARCH-05 | Phase 6 | Complete |

**Coverage:**
- v1.0 requirements: 23 total
- Mapped to phases: 23
- Unmapped: 0 ✓

---
*Requirements defined: 2026-03-03*
*Last updated: 2026-03-04 — 04-02 complete: BEHAV-01, API-03, TEST-01 (querent<S,T> with query() accumulating std::expected results, 6 BDD scenarios, Phase 4 human verification passed) confirmed complete*
