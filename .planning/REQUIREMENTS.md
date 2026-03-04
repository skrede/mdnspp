# Requirements: mdnspp

**Defined:** 2026-03-04
**Core Value:** A C++23 mDNS library that composes naturally with any executor or event loop — no owned threads, no hidden allocations, no C types leaking into user code. Truly standalone.

## v2.0 Requirements

Requirements for milestone v2.0: Standalone & Ergonomic.

### API — Unified Policy Architecture

- [x] **API-01**: Single `Policy` concept merges SocketPolicy + TimerPolicy — all public types use one template parameter (`observer<P>`, `service_discovery<P>`, etc.)
- [x] **API-02**: `MockPolicy` unifies `MockSocketPolicy` + `MockTimerPolicy` into a single test double satisfying the `Policy` concept
- [x] **API-03**: `recv_loop<P>` uses single Policy parameter — mechanical migration from `recv_loop<S,T>`
- [x] **API-04**: `AsioPolicy` bundles socket + timer operations, constructible from `asio::io_context&`

### API — Construction & Error Handling

- [x] **API-05**: Direct construction via constructor — `observer<AsioPolicy>(io, cb)` works without factory function
- [x] **API-06**: Constructor throws `std::system_error` on failure (ASIO convention)
- [x] **API-07**: Non-throwing `error_code` overload — `observer<AsioPolicy>(io, cb, ec)` sets error code instead of throwing
- [x] **API-08**: `create()` factory removed from all public types

### API — Completion Tokens

- [x] **API-09**: All async operations accept ASIO completion tokens via `async_initiate`
- [x] **API-10**: Callback path — `async_discover(callback)` fires callback with result
- [x] **API-11**: Future path — `async_discover(asio::use_future)` returns `std::future<T>`
- [x] **API-12**: Coroutine path — `co_await async_discover(asio::use_awaitable)` returns awaitable
- [x] **API-13**: Deferred path — `async_discover(asio::deferred)` returns composable deferred operation

### PROTO — Native C++ Protocol

- [x] **PROTO-01**: `read_dns_name` implements RFC 1035 §4.1.4 name decompression with RFC 9267 safety (backward-only pointers, hop limit, name length limit)
- [x] **PROTO-02**: Native C++ record parsing replaces all mjansson/mdns parse calls in `src/`
- [x] **PROTO-03**: mjansson/mdns C library fully removed (FetchContent, link targets, includes)
- [x] **PROTO-04**: All existing record types (PTR, SRV, A, AAAA, TXT) parse correctly via native implementation
- [x] **PROTO-05**: Existing unit tests pass against native parser with no behavioral changes

### NET — Standalone Networking

- [x] **NET-01**: `NativePolicy` provides raw UDP socket operations without ASIO
- [x] **NET-02**: `NativePolicy` provides timer operations using OS primitives
- [x] **NET-03**: `NativePolicy::run()` blocks and processes I/O (mirrors `io_context::run()`)
- [x] **NET-04**: `NativePolicy::poll()` / `poll_one()` process ready I/O without blocking
- [x] **NET-05**: IPv4 multicast group join (`224.0.0.251:5353`) on all interfaces
- [x] **NET-06**: Cross-platform: Linux, macOS, Windows (`poll()` / `WSAPoll()`)
- [x] **NET-07**: All four public types work with `NativePolicy` — `observer<NativePolicy>(native, cb)` compiles and runs

### AGG — Service Aggregation

- [ ] **AGG-01**: `resolved_service` struct combining service name, hostname, port, TXT records, and IP addresses
- [ ] **AGG-02**: Correlation logic aggregates PTR → SRV → TXT → A/AAAA records into `resolved_service`
- [ ] **AGG-03**: Discovery can return `resolved_service` instead of raw `mdns_record_variant`
- [ ] **AGG-04**: Aggregation handles partial responses (service discovered without all record types yet)

## v2.1 Requirements

Deferred to future release. Tracked but not in current roadmap.

### Memory

- **MEM-01**: Transparent memory model — no hidden allocations, user controls buffers
- **MEM-02**: PMR / allocator-aware containers (`std::pmr::vector`, `std::pmr::string` in record types)
- **MEM-03**: Policy injects `memory_resource*` for allocator propagation

### Compliance

- **COMP-01**: RFC 6762 conflict resolution — 3 probes at 250ms, unicast-response bit, lexicographic tiebreak
- **COMP-02**: Unsolicited announcements — 2 announces at 1s intervals after successful probe
- **COMP-03**: Name uniqueness enforcement — automatic rename on conflict detection

## Out of Scope

| Feature | Reason |
|---------|--------|
| Full DNS resolver | Different protocol, different scope |
| ROS2 integration | Middleware is a separate project; mdnspp exposes interfaces |
| Mobile platforms (iOS/Android) | Not a current target |
| mDNS-SD extensions beyond RFC 6762/6763 | Stay RFC-compliant |
| Boost.ASIO | Standalone ASIO only (non-Boost) |
| Thread ownership inside NativePolicy | Breaks "no owned threads" core constraint — user drives run()/poll() |
| DNS name compression in outgoing packets | Optional per RFC 1035, irrelevant at mDNS MTU |
| Synchronous blocking discover() as primary API | Async is primary; sync is a convenience wrapper |

## Traceability

Which phases cover which requirements. Updated during roadmap creation.

| Requirement | Phase | Status |
|-------------|-------|--------|
| API-01 | Phase 7 | Complete |
| API-02 | Phase 7 | Complete |
| API-03 | Phase 7 | Complete |
| API-04 | Phase 7 | Complete |
| API-05 | Phase 7 | Complete |
| API-06 | Phase 7 | Complete |
| API-07 | Phase 7 | Complete |
| API-08 | Phase 7 | Complete |
| API-09 | Phase 10 | Complete |
| API-10 | Phase 10 | Complete |
| API-11 | Phase 10 | Complete |
| API-12 | Phase 10 | Complete |
| API-13 | Phase 10 | Complete |
| PROTO-01 | Phase 8 | Complete |
| PROTO-02 | Phase 8 | Complete |
| PROTO-03 | Phase 8 | Complete |
| PROTO-04 | Phase 8 | Complete |
| PROTO-05 | Phase 8 | Complete |
| NET-01 | Phase 9 | Complete |
| NET-02 | Phase 9 | Complete |
| NET-03 | Phase 9 | Complete |
| NET-04 | Phase 9 | Complete |
| NET-05 | Phase 9 | Complete |
| NET-06 | Phase 9 | Complete |
| NET-07 | Phase 9 | Complete |
| AGG-01 | Phase 11 | Pending |
| AGG-02 | Phase 11 | Pending |
| AGG-03 | Phase 11 | Pending |
| AGG-04 | Phase 11 | Pending |

**Coverage:**
- v2.0 requirements: 29 total
- Mapped to phases: 29
- Unmapped: 0

---
*Requirements defined: 2026-03-04*
*Last updated: 2026-03-04 after v2.0 roadmap creation*
