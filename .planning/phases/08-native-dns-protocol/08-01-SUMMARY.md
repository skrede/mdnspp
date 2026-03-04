---
phase: 08-native-dns-protocol
plan: 01
subsystem: dns-wire-format
tags: [dns, parsing, rfc1035, rfc9267, tdd, c++23]
dependency_graph:
  requires: []
  provides: [detail::read_dns_name]
  affects: [src/mdnspp/dns_wire.h]
tech_stack:
  added: []
  patterns: [std::expected, std::span, TDD RED/GREEN]
key_files:
  created:
    - tests/dns_wire_test.cpp
  modified:
    - src/mdnspp/dns_wire.h
    - tests/CMakeLists.txt
decisions:
  - "No trailing dot in assembled names — cleaner than mjansson; existing parse_test uses find() not == so no regressions"
  - "read_dns_name uses by-value offset parameter (not reference) — caller retains original offset; different contract from skip_dns_name by design"
metrics:
  duration: "~4 min"
  completed: "2026-03-04"
  tasks_completed: 1
  files_modified: 3
---

# Phase 8 Plan 1: read_dns_name — RFC 1035 Name Decompression Summary

**One-liner:** RFC 1035 §4.1.4 DNS name decompression with RFC 9267 safety (backward-only pointers, 4-hop limit, 255-byte cap) returning `std::expected<std::string, mdns_error>`.

## What Was Built

`detail::read_dns_name()` added to `src/mdnspp/dns_wire.h` in the `mdnspp::detail` namespace. The function decodes DNS wire-format names including compression pointer following, assembles the dotted-label string, and enforces all RFC 9267 safety constraints.

### Function Signature

```cpp
inline std::expected<std::string, mdns_error>
read_dns_name(std::span<const std::byte> buf, size_t offset);
```

### Safety Properties

| Constraint | Value | RFC Reference |
|------------|-------|---------------|
| Pointer direction | Backward-only (`ptr_target < offset`) | RFC 9267 |
| Max pointer hops | 4 | RFC 9267 |
| Max assembled name length | 255 bytes | RFC 1035 §3.1 |
| Self-referential `{0xC0, 0x0C}` at offset 12 | Rejected by backward-only check | Phase 8 success criterion #2 |

### Test Coverage (13 test cases)

Happy path:
- Simple uncompressed name `_http._tcp.local`
- Root-only name (empty string)
- Single-label name `host`
- Backward compression pointer with inline labels before
- Name starting directly at a bare compression pointer

Safety rejections (all return `parse_error`):
- Self-referential pointer `{0xC0, 0x0C}` at offset 12
- Forward pointer (`ptr_target >= offset`)
- 5-hop chain (exceeds limit of 4)
- 4-hop chain (passes — boundary test)
- Name exceeding 255 bytes
- Truncated buffer mid-label
- Truncated buffer mid-pointer (only 1 byte for 2-byte pointer)
- Offset beyond buffer size

## Deviations from Plan

None — plan executed exactly as written.

## Decisions Made

1. **No trailing dot in assembled names:** The plan specified "no trailing dot (match test expectations; existing tests use `find()` not `==`)". This was confirmed correct — `parse_test.cpp` uses `find("_http")` throughout. The new `dns_wire_test.cpp` asserts exact equality `== "_http._tcp.local"` without trailing dot, establishing the canonical format for Phase 02 integration.

2. **`read_dns_name` takes offset by value, not by reference:** `skip_dns_name` advances the offset in-place (pass-by-reference), which is appropriate for a cursor that `walk_dns_frame` needs to advance. `read_dns_name` decodes the name from a fixed start point without side effects on the caller's cursor. This matches the Phase 02 usage pattern where `parse.cpp` will call `read_dns_name(buffer, meta.name_offset)` — the offset is a snapshot, not a cursor.

## Self-Check

Checked:
- `src/mdnspp/dns_wire.h` — FOUND
- `tests/dns_wire_test.cpp` — FOUND
- `tests/CMakeLists.txt` contains `make_test(dns_wire_test)` — FOUND
- Commit `d9186ed` (RED — failing tests) — FOUND
- Commit `50e600b` (GREEN — implementation) — FOUND
- All 10 tests pass, including all 13 dns_wire_test cases — VERIFIED

## Self-Check: PASSED
