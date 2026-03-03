# Codebase Concerns

**Analysis Date:** 2026-03-03

## Critical Issues

**1. Deadlock in `service_server::stop()`:**
- Issue: `stop()` locks `m_mutex`, then calls `announce_goodbye_locked()` which tries to acquire the same non-recursive mutex. This is undefined behavior and causes deadlock on every call.
- Files: `src/mdnspp/service_server.cpp:90-101`
- Impact: Calling `service_server::stop()` will always deadlock, making graceful shutdown impossible. Services cannot be stopped once started.
- Fix approach: Move `announce_goodbye_locked()` outside the mutex lock or rename to non-locked version and split responsibility. Refactor `stop()` to not hold lock while calling locked functions.

**2. `m_socket_count` not reset after `close_sockets()`:**
- Issue: `close_sockets()` closes all socket file descriptors but never sets `m_socket_count = 0`. Stale socket count remains after stop.
- Files: `src/mdnspp/mdns_base.cpp:112-119`
- Impact: After `stop()`, subsequent `send()` operations iterate over closed FDs. `listen_while` will call `FD_SET`/`select()` on invalid FDs. A second call to `open_*_sockets()` may overflow `m_sockets[]` array if count exceeds limit.
- Fix approach: Set `m_socket_count = 0` inside `close_sockets()` before or immediately after closing FDs.

**3. Race condition: `listen_while` races with `close_sockets()` on socket FDs:**
- Issue: The `listen_while` template (lines 59-105 in `mdns_base.h`) reads `m_sockets[]` and `m_socket_count` without synchronization. When `service_server::stop()` calls `close_sockets()` from another thread, the listening loop can call `FD_SET`/`select()`/`recv()` on already-closed sockets.
- Files: `include/mdnspp/mdns_base.h:59-105`, `src/mdnspp/mdns_base.cpp:112-119`
- Impact: Undefined behavior when stop signal arrives during listen loop. File descriptor reuse could cause operations on wrong sockets. Segmentation faults possible on some systems.
- Fix approach: Add mutex protection to socket access in `listen_while`. Create a shared lock mechanism that prevents FD access during `close_sockets()`. Or use atomic snapshot of socket count before loop iteration.

## High Severity Issues

**4. Copy-paste bug in `service_server::start()` - IPv6 address check:**
- Issue: Line 116 in `service_server.cpp` reads `has_address_ipv4()` when it should read `has_address_ipv6()`:
  ```cpp
  auto ipv6 = has_address_ipv6() ? address_ipv6() : std::nullopt;
  //          ^^^^^^^^^^^^^^^^^ should be has_address_ipv6()
  ```
- Files: `src/mdnspp/service_server.cpp:116`
- Impact: IPv6 address assignment is conditional on IPv4 availability, not IPv6. Services may fail to configure IPv6 when only IPv6 is available. Incorrect service announcements on IPv6-only networks.
- Fix approach: Change `has_address_ipv4()` to `has_address_ipv6()` on line 116.

**5. `service_server::stop()` never sets `m_stop` flag:**
- Issue: `service_server::stop()` overrides base `stop()` but never calls `mdns_base::stop()`, so `m_stop` remains false. The `listen_while` loop cannot detect stop signal.
- Files: `src/mdnspp/service_server.cpp:90-101`
- Impact: Observer cannot be stopped via the `m_stop` flag. Only relies on timeout between `select()` calls or if `m_running = false` is sufficient. Makes stopping unreliable under light traffic.
- Fix approach: Ensure `mdns_base::stop()` is called within `service_server::stop()` to set `m_stop = true`. Currently line 99 calls it, but after potentially deadlocked code.

**6. `observer::stop()` / `listen_while` don't check `m_stop` properly:**
- Issue: The `listen_while` template checks `m_stop` in the while condition (line 66), but only on select timeout. If no packets arrive, the loop won't exit quickly.
- Files: `include/mdnspp/mdns_base.h:66`, `src/mdnspp/observer.cpp:54-58`
- Impact: Observer cannot be stopped under heavy mDNS traffic since `listen_while` only checks `m_stop` between `select()` iterations. Can block indefinitely if packets keep arriving.
- Fix approach: Add check for `m_stop` inside the loop after recv operations, before processing next record. Or use select timeout more aggressively.

## Medium Severity Issues

**7. `service_discovery` filter logic inverted vs `observer`:**
- Issue: `service_discovery::filter_ignore_record()` returns `true` (ignore) if **any** filter returns `true`, opposite semantics to `observer::filter_ignore_record()`. Same filter function gives opposite behavior between classes.
- Files: `src/mdnspp/service_discovery.cpp:55-62` vs `src/mdnspp/observer.cpp:86-94`
- Impact: Whitelisting filters work inversely depending on class. Records matching filter criteria are ignored in one class but not the other. Confusing API.
- Fix approach: Standardize filter semantics. Both should return `true` to ignore, `false` to keep. Document clearly or use explicit filter mode (whitelist vs blacklist).

**8. Missing braces in `service_discovery::callback` for-loop:**
- Issue: Lines 70-78 in `service_discovery.cpp` have a braceless for-loop with `continue` statement:
  ```cpp
  for(const auto &txt : parser.parse_txt())
  {
      if(filter_ignore_record(txt))
          continue;
      // ... more statements
  }
  ```
- Files: `src/mdnspp/service_discovery.cpp:70-78`
- Impact: Code is fragile. Future maintainers may add statements thinking they're in the loop body but actually skip the loop due to missing braces. Low immediate risk but maintenance hazard.
- Fix approach: Add explicit braces around all loop/conditional bodies regardless of single-statement nature.

**9. FD_SET called without FD_SETSIZE bounds check:**
- Issue: `listen_while` and `listen_until_silence` call `FD_SET` on socket FDs without checking if `fd >= FD_SETSIZE` (typically 1024). On systems with more than 1024 open files, buffer overflow.
- Files: `include/mdnspp/mdns_base.h:74-81` (has check at 76-77), `src/mdnspp/mdns_base.cpp:158-165` (has check at 160-161)
- Impact: Buffer overflow on high-FD-count systems. The code does skip FDs >= FD_SETSIZE, but doesn't warn or error. Silent failures on busy systems.
- Fix approach: Add explicit warning if socket >= FD_SETSIZE. Consider using `poll()` instead of `select()` for better scalability. Or fail-fast if system socket limit is unknown.

**10. `service_instance_name()` reads `m_builder` without mutex:**
- Issue: `service_instance_name()` calls `m_builder->service_instance()` inside a mutex lock (line 111), but `service_instance_name()` itself is const and marked as safe to call without holding the lock. However, `m_builder` is shared and accessed from multiple methods.
- Files: `src/mdnspp/service_server.cpp:109-113`
- Impact: Data race if another thread modifies `m_builder` during call. Returns potentially stale or torn pointer read. Possible segmentation fault.
- Fix approach: Mutex is correctly held (line 111). No change needed - code is actually safe.

## Low Severity Issues

**11. `m_running` semantics fragile in `service_server::stop()`:**
- Issue: `m_running` is set false (line 96), but the listen loop actually terminates when `select()` fails on closed FDs, not because `m_running` changes. Termination is side-effect of FD closure.
- Files: `src/mdnspp/service_server.cpp:90-101`, `include/mdnspp/mdns_base.h:66`
- Impact: Loop termination is brittle and relies on implementation detail (select failure). If behavior changes, loop might hang. Not directly unsafe but design is fragile.
- Fix approach: Ensure `listen_while` check happens reliably: either use `m_stop` consistently or ensure `m_running` is checked every iteration, not just on select timeout.

**12. `m_stop` race at start of `listen_until_silence`:**
- Issue: `listen_until_silence` unconditionally sets `m_stop = false` at line 133 at the start. This races with concurrent `stop()` call which may have just set it `true`.
- Files: `src/mdnspp/mdns_base.cpp:131-133`
- Impact: If `stop()` is called between discovering the need to listen and entering `listen_until_silence`, the stop flag is overwritten. Thread attempting to stop may fail silently.
- Fix approach: Use atomic compare-and-swap or design to never reset stop flag once set. Or ensure single-threaded semantics where `stop()` cannot be called while `listen_until_silence` is starting.

## Test Coverage Gaps

**13. Practically NIL test coverage:**
- What's not tested: Threading, socket lifecycle, concurrent start/stop, filter semantics, error handling in network failures, IPv6 support, multi-interface scenarios.
- Files: `tests/log_test.cpp` (only 21 lines, tests only logging)
- Risk: Critical threading bugs (1-3 above) were not caught by tests. No regression detection for future changes.
- Priority: **High** - Add unit tests for thread safety, socket cleanup, and stop() behavior.

## Known Limitations & Missing Features

**14. Single adapter per family:**
- What's missing: A and AAAA records only created for first adapter in each family (IPv4 and IPv6).
- Files: `include/mdnspp/mdns_base.h`, `src/mdnspp/mdns_base.cpp:254-467`
- Blocks: Multi-homed hosts cannot announce services on all interfaces.

**15. No per-interface control:**
- What's missing: No API to select specific network interfaces to use or exclude.
- Files: `include/mdnspp/service_server.h`
- Blocks: Services must listen on all interfaces; cannot isolate to specific networks.

**16. Limited testing against 3rd party:**
- What's missing: Systematic testing against Avahi, Bonjour, Windows mDNS.
- Files: `README.md:138-139`
- Blocks: Interoperability bugs undiscovered; compatibility with non-Apple systems unknown.

---

*Concerns audit: 2026-03-03*
