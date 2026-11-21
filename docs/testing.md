# Test Landscape

mdnspp has four test categories: unit tests, integration tests, fuzz tests,
and compile tests. This page describes what each category validates and how to
run it.

## Unit tests

**Location:** `tests/unit/`
**Framework:** [Catch2](https://github.com/catchorg/Catch2)
**Policy:** `mock_policy` (no real sockets or timers)

Unit tests exercise individual components in isolation. `mock_policy` replaces
real network I/O with controllable in-process fakes:

- `mock_socket` — exposes `sent_packets()` for inspection and accepts manually
  enqueued inbound packets.
- `mock_timer` — supports manual `fire()` and `cancel()` for deterministic
  timer control.
- `mock_executor` — holds a posted-work deque that drains with
  `drain_posted()`.

Unit tests cover:

- DNS wire format encoding and decoding (tests/unit/dns_wire/:
  dns_wire_*_test; dns_test; tests/unit/parse/: parse_*_test)
- DNS name serialization and round-trips (dns_name_test)
- DNS-SD service type parsing (service_type_test)
- Record and service description construction (records_test,
  service_info_test, service_info_make_test, mdns_util_test)
- State machine correctness: probe/announce/live/stopped lifecycle, query
  matching and response construction (server_probe_announce_test,
  server_query_match_test; tests/unit/server/: server_*_test)
- Cache operations: TTL expiry, refresh, goodbye processing (tests/unit/cache/:
  cache_*_test; ttl_refresh_test)
- Known-answer suppression logic (server_known_answer_test)
- TC accumulation across multi-packet responses (tc_accumulator_test)
- Query deduplication and response aggregation (server_response_aggregation_test,
  duplicate_answer_suppression_test)
- Service monitor and discovery aggregation (tests/unit/monitor/:
  monitor_*_test; tests/unit/discovery/: discovery_*_test;
  service_aggregation_test)
- Observer raw packet delivery (tests/unit/observer/: observer_*_test)
- Querier query construction and result delivery (tests/unit/querier/:
  querier_*_test; query_backoff_test)
- Endpoint, sender address text and socket option handling (endpoint_test,
  sockaddr_text_test, socket_options_test)
- Interface enumeration and binding resolution (enumerate_interfaces_test,
  interface_resolve_test)
- Receive-loop lifecycle, delivery, error propagation and stop behavior
  (tests/unit/recv_loop/: recv_loop_*_test)
- Receive ancillary data: TTL, hop limit and arrival interface, including
  truncated control data (recv_ancillary_test, recv_ancillary_bounds_test)
- The receive contract every socket honors: one completion per arm, ordering,
  and close semantics (tests/unit/receive_contract/: receive_contract_*_test)
- Default event loop: socket registry, timer dispatch, poll errors, re-entrant
  polling from a receive handler and the handler's data across nested polls,
  wakeup descriptor, construction failures and cross-thread posting
  (socket_registry_test, default_timer_test, default_timer_dispatch_test,
  default_poll_errors_test, default_reentrant_poll_test,
  default_nested_receive_test, wakeup_fd_test, default_context_construct_test,
  post_queue_seam_test, post_stress_test)
- Multi-NIC orchestration: group instance lifecycle, dynamic builder, and
  interface monitoring (tests/unit/nic_group/: nic_group_server_test,
  nic_group_monitor_test, nic_group_options_test; nic_group_dynamic_test,
  nic_monitor_test)
- Multicast capability validation (validate_multicast_test)
- Encrypt component (tests/unit/encrypt/): AEAD encrypt/decrypt and tamper
  detection (encrypt_aead_*_test), replay window, per-sender and per-session
  bounds (encrypt_replay_*_test), epoch-based key rotation and grace periods
  (encrypt_key_rotation_*_test), socket framing and cleartext detection modes
  (encrypt_socket_*_test), receive-side rejection, cleartext handling and
  re-arming (encrypt_receive_*_test, including encrypt_receive_rearm_test),
  policy/trait conformance (encrypt_policy_test, encrypt_policy_trait_test)
- Encrypt allocation windows: steady-state send and receive allocate nothing
  over the mock socket and over the default socket on IPv4 and IPv6, and no
  more than a plain asio receive loop over the asio socket on IPv4 and IPv6;
  filling the receive metadata allocates nothing (encrypt_no_alloc_test; not
  built under `-fsanitize=thread`)
- policy_like concept conformance for all built-in policies
  (concept_conformance_test, inproc_conformance_test, asio_conformance_test;
  tests/unit/default_conformance/: default_conformance_construct_test,
  default_conformance_send_receive_test, default_conformance_lifecycle_test,
  default_conformance_receive_metadata_test,
  default_conformance_ipv6_interface_test)
- Test-double sockets: the error_code constructors and send of the mock and
  in-process sockets, the throwing forms that wrap them, and the mock socket's
  failure injection reaching both (mock_socket_error_code_test,
  inproc_socket_error_code_test)
- asio backend: IPv6 interface binding (asio_ipv6_interface_test), peer
  destruction with a pending receive (asio_peer_destroy_test), and completion
  tokens (tests/unit/asio_token/: asio_token_*_test)
- Cross-thread server stop/update races (tests/unit/asio_tsan/:
  asio_tsan_server_test, asio_tsan_updates_test; exercised under
  `-fsanitize=thread` in the CI `sanitize (tsan)` job)
- C++20/C++23 compatibility shims: `expected` and `move_only_function` surface
  and storage, and ODR agreement between the two standards (tests/unit/compat/:
  expected_surface_test and its C++23 build, move_only_function_test,
  compat_odr_test)
- Fuzz harness input decoding (fuzz_input_test)

Some targets depend on the platform or build options:
default_poll_errors_test, default_reentrant_poll_test,
default_nested_receive_test, wakeup_fd_test, default_context_construct_test,
recv_ancillary_bounds_test and
default_conformance_receive_metadata_test are not built on Windows; the
`asio_*` targets and receive_contract_asio_test require
`MDNSPP_ENABLE_ASIO_POLICY=ON`; the encrypt targets other than
encrypt_policy_trait_test, and receive_contract_encrypted_test, require
`MDNSPP_ENABLE_ENCRYPT=ON`.

**How to run:**

```bash
cmake -B build
cmake --build build
ctest --test-dir build
```

To run a specific test file:

```bash
ctest --test-dir build -R dns_name_test
```

## Protocol integration tests (inproc)

**Location:** `tests/unit/inproc_bus_*.cpp`, `tests/unit/inproc_rfc/` and
`tests/unit/inproc_legacy_unicast/` (compiled with the unit test suite; targets
`inproc_bus_*_test`, `inproc_rfc_*_test` and `inproc_legacy_unicast_*_test`)
**Framework:** Catch2
**Policy:** `inproc_test_policy` (test_clock via `inproc_harness`)

These tests exercise multi-party mDNS scenarios end-to-end using the
deterministic in-process bus. All network I/O stays in-process. `inproc_harness`
provides a shared `inproc_bus<test_clock>` and `inproc_executor<test_clock>` so
tests can advance simulated time with `h.advance(ms)` instead of sleeping.

Beyond the ten core scenarios below, dedicated suites cover legacy unicast
responses (`inproc_legacy_unicast/`, using
`inproc_socket_options::port_override` to simulate a non-5353 source port),
per-record-type TTLs (`inproc_bus_per_type_ttl_test.cpp`), receive-side TTL
enforcement (`inproc_bus_recv_ttl_test.cpp`), TC continuation delays
(`inproc_bus_tc_delay_test.cpp`), and automatic address resolution from the
bound interface (`inproc_bus_auto_address_test.cpp`).

The ten core scenarios:

| ID | Scenario | Files |
|----|----------|-------|
| TEST-01 | Probe conflict resolution — two servers with the same name | `inproc_bus_discovery_test.cpp` |
| TEST-02 | Discovery lifecycle — server announces, monitor finds, server stops, monitor loses | `inproc_bus_discovery_test.cpp` |
| TEST-03 | Known-answer suppression — querier suppresses records already in query | `inproc_rfc/known_answer.cpp` |
| TEST-04 | Duplicate answer suppression across queriers | `inproc_rfc/duplicate_answer.cpp` |
| TEST-05 | Observer captures all traffic — probes, announces, queries, responses | `inproc_bus_routing_test.cpp` |
| TEST-06 | TC bit multi-packet accumulation end-to-end | `inproc_rfc/tc_accumulation.cpp` |
| TEST-07 | Cache-flush propagation across monitors | `inproc_rfc/cache_flush.cpp` |
| TEST-08 | Query backoff convergence — exponential backoff on repeated queries | `inproc_bus_routing_test.cpp` |
| TEST-09 | Multiple service types — type-specific monitors see only their type | `inproc_bus_routing_test.cpp` |
| TEST-10 | Goodbye with delayed expiry — `on_lost` does not fire before grace period | `inproc_bus_discovery_test.cpp` |

These tests run as part of the standard unit test suite and require no
additional build flags.

## Install-consume integration test

**Location:** `tests/integration/`
**Entry point:** `tests/integration/run.sh`

Validates the installed CMake package: the script builds and installs mdnspp
into a temporary prefix, then configures a standalone consumer project with
`find_package(mdnspp CONFIG REQUIRED COMPONENTS inproc testing)` and links
`mdnspp::mdnspp`, `mdnspp::inproc`, `mdnspp::testing`, and — when the
corresponding components were installed — `mdnspp::asio` and
`mdnspp::encrypt`. The consumer deliberately sets no `CMAKE_CXX_STANDARD`:
it must inherit `cxx_std_20` from the exported targets'
`INTERFACE_COMPILE_FEATURES`. This catches export-name drift, dangling
component references, and standard-propagation regressions that the build
tree masks.

## Fuzz tests

**Location:** `tests/fuzz/`
**Framework:** [libFuzzer](https://llvm.org/docs/LibFuzzer.html) (Clang only)
**Build flag:** `MDNSPP_BUILD_FUZZ_TESTS=ON`

Fuzz tests feed randomly mutated byte sequences into the DNS parsing and
serialization layer to discover crashes, assertion failures, and
undefined-behavior sanitizer trips caused by malformed input. libFuzzer drives
mutation and uses coverage feedback to guide the corpus toward interesting code
paths.

Fourteen harnesses are provided:

| Harness | Target |
|---------|--------|
| `fuzz_dns_name` | `dns_name` construction from raw bytes |
| `fuzz_encode_dns_name` | DNS name wire encoding |
| `fuzz_read_dns_name` | Low-level name reader |
| `fuzz_skip_dns_name` | Name-skip cursor arithmetic |
| `fuzz_roundtrip_dns_name` | Name encode→decode round-trip |
| `fuzz_roundtrip_name` | Higher-level name round-trip |
| `fuzz_parse_a` | A record parser |
| `fuzz_parse_aaaa` | AAAA record parser |
| `fuzz_parse_ptr` | PTR record parser |
| `fuzz_parse_srv` | SRV record parser |
| `fuzz_parse_txt` | TXT record parser |
| `fuzz_walk_dns_frame_raw` | Full DNS frame walker (raw callback) |
| `fuzz_walk_dns_frame_smart` | Full DNS frame walker (typed record callback) |
| `fuzz_encrypted_packet` | Encrypted packet handling (requires `MDNSPP_ENABLE_ENCRYPT=ON`); two modes selected by the first input byte: raw attacker-controlled bytes into the decrypt path, and a round-trip mode that encrypts an input-derived payload with the real key, mutates it, and drives the full receive path across cleartext-detection modes, `receive_mode` filtering, and epoch handling |

`fuzz_encrypted_packet` reads multi-byte fields from the input through
`tests/fuzz/fuzz_input.h`, which reads bytes in a fixed sequence and decodes
high byte first, so a corpus entry replays identically with every compiler;
fuzz_input_test covers that decoder in the unit suite.

Seeds are generated at build time by `generate_corpus.cpp` into
`${CMAKE_BINARY_DIR}/fuzz_corpus/<category>/`. The `fuzz_corpus` ALL custom
target regenerates seeds at every build. Category names (e.g., `walk_frame`,
`roundtrip`, `dns_name`) group seeds by function, not by harness binary name.

**How to build (Clang required):**

```bash
cmake -B build -DCMAKE_CXX_COMPILER=clang++ -DMDNSPP_BUILD_FUZZ_TESTS=ON
cmake --build build
```

**How to run a single harness:**

```bash
./build/tests/fuzz/fuzz_walk_dns_frame_smart \
    build/fuzz_corpus/walk_frame/ \
    -max_total_time=60
```

**How to run all harnesses (as in CI):**

The CI workflow (`fuzz.yml`) runs every harness for 60 seconds each and
aggregates exit codes so all harnesses run before the job fails. It triggers
on pushes and pull requests for `master`, `develop`, `hardening`, and `fuzz`,
and accumulates the corpus across runs via the GitHub Actions cache, so
coverage compounds rather than restarting from the generated seeds.

## Compile tests

**Location:** `tests/compile/`
**Purpose:** Concept conformance and header correctness

Compile tests contain no runtime assertions — they succeed if they compile and
link. They verify:

- `defaults_compile_test.cpp` — `defaults.h` type aliases compile and the
  template instantiations are valid.
- `infra_headers_compile_test.cpp` — every public and detail header of the
  core library is included by one translation unit, ordered so that leaf
  headers precede the aggregating ones, catching missing-include regressions.
- `encrypt_defaults_compile_test.cpp` — the encrypt convenience aliases
  compile (built only with `MDNSPP_ENABLE_ENCRYPT=ON`).

Compile tests run as part of the standard build and are included in `ctest`.

## Sanitizer jobs in CI

The Linux workflow runs the full test suite (including asio and encrypt) in
two additional configurations on Clang:

- **asan-ubsan** — `-fsanitize=address,undefined -fno-sanitize-recover=all`
- **tsan** — `-fsanitize=thread`; this is the configuration under which
  `asio_tsan_server_test` and `asio_tsan_updates_test` exercise cross-thread
  `stop()` / `update_service_info` races meaningfully. The allocation-counting
  encrypt_no_alloc_test is not built in this configuration.

## Standard library

The Linux jobs build against libstdc++; the macOS job builds against libc++
(AppleClang). On Linux, the suite can also run against libc++ with clang and
`-stdlib=libc++`. A system Catch2 is built against libstdc++ and cannot link
into a libc++ test binary, so this configuration enables
`MDNSPP_CMAKE_FETCH_DEPS`, which builds Catch2, asio and libsodium from the
sources pinned in the CMake files:

    CC=clang CXX=clang++ cmake -S . -B build-libcxx -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_CXX_FLAGS="-stdlib=libc++" -DMDNSPP_BUILD_TESTS=ON \
      -DMDNSPP_BUILD_EXAMPLES=ON -DMDNSPP_ENABLE_ASIO_POLICY=ON \
      -DMDNSPP_ENABLE_ENCRYPT=ON -DMDNSPP_CMAKE_FETCH_DEPS=ON

## See also

- [inproc-bus.md](inproc-bus.md) — inproc_policy production guide (steady_clock, `run()`)
- [policies.md](policies.md) — mock_policy unit testing setup
- [custom-policies.md](custom-policies.md) — inproc_policy concept walkthrough
