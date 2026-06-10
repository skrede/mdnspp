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

- DNS wire format encoding and decoding (dns_wire_test, dns_test, parse_test)
- DNS name serialization and round-trips (dns_name_test)
- Record construction and equality (records_test)
- State machine correctness: probe/announce/live/stopped lifecycle
  (server_probe_announce_test, server_query_match_test)
- Cache operations: TTL expiry, refresh, goodbye processing (record_cache_test,
  ttl_refresh_test)
- Known-answer suppression logic (server_known_answer_test)
- TC accumulation across multi-packet responses (tc_accumulator_test)
- Query deduplication and response aggregation (server_response_aggregation_test,
  duplicate_answer_suppression_test)
- Service monitor and discovery aggregation (service_monitor_test,
  service_discovery_test, service_aggregation_test)
- Observer raw packet delivery (observer_test)
- Querier query construction and result delivery (querier_test, query_backoff_test)
- Endpoint and socket option handling (endpoint_test, socket_options_test)
- Receive-loop error propagation and TTL filtering (recv_loop_test)
- Multi-NIC orchestration: group instance lifecycle, dynamic builder, and
  interface monitoring (nic_group_test, nic_group_dynamic_test, nic_monitor_test)
- Multicast capability validation (validate_multicast_test)
- Encrypt component: AEAD encrypt/decrypt and tamper detection
  (encrypt_aead_test), replay window (encrypt_replay_window_test), epoch-based
  key rotation and grace periods (encrypt_key_rotation_test), socket framing
  and cleartext detection modes (encrypt_socket_test), policy/trait conformance
  (encrypt_policy_test, encrypt_policy_trait_test)
- policy_like concept conformance for all built-in policies
  (concept_conformance_test, default_conformance_test, inproc_conformance_test,
  asio_conformance_test)
- Cross-thread server stop/update races (service_server_tsan_test; exercised
  under `-fsanitize=thread` in the CI `sanitize (tsan)` job)

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

**Location:** `tests/unit/inproc_bus_*.cpp` (compiled with the unit test suite)
**Framework:** Catch2
**Policy:** `inproc_test_policy` (test_clock via `inproc_harness`)

These tests exercise multi-party mDNS scenarios end-to-end using the
deterministic in-process bus. All network I/O stays in-process. `inproc_harness`
provides a shared `inproc_bus<test_clock>` and `inproc_executor<test_clock>` so
tests can advance simulated time with `h.advance(ms)` instead of sleeping.

Beyond the ten core scenarios below, dedicated suites cover legacy unicast
responses (`inproc_bus_legacy_unicast_test.cpp`, using
`inproc_socket_options::port_override` to simulate a non-5353 source port),
per-record-type TTLs (`inproc_bus_per_type_ttl_test.cpp`), receive-side TTL
enforcement (`inproc_bus_recv_ttl_test.cpp`), and TC continuation delays
(`inproc_bus_tc_delay_test.cpp`).

The ten core scenarios:

| ID | Scenario | Files |
|----|----------|-------|
| TEST-01 | Probe conflict resolution — two servers with the same name | `inproc_bus_discovery_test.cpp`, `inproc_bus_rfc_compliance_test.cpp` |
| TEST-02 | Discovery lifecycle — server announces, monitor finds, server stops, monitor loses | `inproc_bus_discovery_test.cpp`, `inproc_bus_rfc_compliance_test.cpp` |
| TEST-03 | Known-answer suppression — querier suppresses records already in query | `inproc_bus_rfc_compliance_test.cpp` |
| TEST-04 | Duplicate answer suppression across queriers | `inproc_bus_rfc_compliance_test.cpp` |
| TEST-05 | Observer captures all traffic — probes, announces, queries, responses | `inproc_bus_routing_test.cpp` |
| TEST-06 | TC bit multi-packet accumulation end-to-end | `inproc_bus_rfc_compliance_test.cpp` |
| TEST-07 | Cache-flush propagation across monitors | `inproc_bus_rfc_compliance_test.cpp` |
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
  `service_server_tsan_test` exercises cross-thread `stop()` /
  `update_service_info` races meaningfully.

## See also

- [inproc-bus.md](inproc-bus.md) — inproc_policy production guide (steady_clock, `run()`)
- [policies.md](policies.md) — mock_policy unit testing setup
- [custom-policies.md](custom-policies.md) — inproc_policy concept walkthrough
