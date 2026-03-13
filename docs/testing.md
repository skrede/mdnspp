# Test Landscape

mdnspp has four test categories: unit tests, integration tests, fuzz tests,
and compile tests. This page describes what each category validates and how to
run it.

## Unit tests

**Location:** `tests/unit/`
**Framework:** [Catch2](https://github.com/catchorg/Catch2)
**Policy:** `MockPolicy` (no real sockets or timers)

Unit tests exercise individual components in isolation. `MockPolicy` replaces
real network I/O with controllable in-process fakes:

- `MockSocket` — exposes `sent_packets()` for inspection and accepts manually
  enqueued inbound packets.
- `MockTimer` — supports manual `fire()` and `cancel()` for deterministic
  timer control.
- `mock_executor` — holds a posted-work deque that drains with
  `drain_posted()`.

Unit tests cover:

- DNS wire format encoding and decoding (dns_wire_test, dns_test, parse_test)
- DNS name serialisation and round-trips (dns_name_test)
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
- Policy concept conformance for all three built-in policies
  (concept_conformance_test, default_conformance_test, local_conformance_test,
  asio_conformance_test)

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

## Integration tests

**Location:** `tests/unit/local_bus_*.cpp` (compiled with the unit test suite)
**Framework:** Catch2
**Policy:** `LocalTestPolicy` (test_clock via `local_harness`)

Integration tests exercise multi-party mDNS scenarios end-to-end using the
deterministic local bus. All network I/O stays in-process. `local_harness`
provides a shared `local_bus<test_clock>` and `local_executor<test_clock>` so
tests can advance simulated time with `h.advance(ms)` instead of sleeping.

Ten scenarios are covered:

| ID | Scenario | Files |
|----|----------|-------|
| TEST-01 | Probe conflict resolution — two servers with the same name | `local_bus_discovery_test.cpp`, `local_bus_rfc_compliance_test.cpp` |
| TEST-02 | Discovery lifecycle — server announces, monitor finds, server stops, monitor loses | `local_bus_discovery_test.cpp`, `local_bus_rfc_compliance_test.cpp` |
| TEST-03 | Known-answer suppression — querier suppresses records already in query | `local_bus_rfc_compliance_test.cpp` |
| TEST-04 | Duplicate answer suppression across queriers | `local_bus_rfc_compliance_test.cpp` |
| TEST-05 | Observer captures all traffic — probes, announces, queries, responses | `local_bus_routing_test.cpp` |
| TEST-06 | TC bit multi-packet accumulation end-to-end | `local_bus_rfc_compliance_test.cpp` |
| TEST-07 | Cache-flush propagation across monitors | `local_bus_rfc_compliance_test.cpp` |
| TEST-08 | Query backoff convergence — exponential backoff on repeated queries | `local_bus_routing_test.cpp` |
| TEST-09 | Multiple service types — type-specific monitors see only their type | `local_bus_routing_test.cpp` |
| TEST-10 | Goodbye with delayed expiry — `on_lost` does not fire before grace period | `local_bus_discovery_test.cpp` |

Integration tests run as part of the standard unit test suite and require no
additional build flags.

## Fuzz tests

**Location:** `tests/fuzz/`
**Framework:** [libFuzzer](https://llvm.org/docs/LibFuzzer.html) (Clang only)
**Build flag:** `MDNSPP_BUILD_FUZZ_TESTS=ON`

Fuzz tests feed randomly mutated byte sequences into the DNS parsing and
serialisation layer to discover crashes, assertion failures, and
undefined-behaviour sanitizer trips caused by malformed input. libFuzzer drives
mutation and uses coverage feedback to guide the corpus toward interesting code
paths.

Thirteen harnesses are provided:

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

Each harness has a seed corpus in `tests/fuzz/corpus/<harness>/` generated by
`generate_corpus.cpp`. The corpus is regenerated at every build to stay in sync
with the source.

**How to build (Clang required):**

```bash
cmake -B build -DCMAKE_CXX_COMPILER=clang++ -DMDNSPP_BUILD_FUZZ_TESTS=ON
cmake --build build
```

**How to run a single harness:**

```bash
./build/tests/fuzz/fuzz_walk_dns_frame_smart \
    tests/fuzz/corpus/fuzz_walk_dns_frame_smart/ \
    -max_total_time=60
```

**How to run all harnesses (as in CI):**

The CI workflow (`fuzz.yml`) runs every harness for 60 seconds each and
aggregates exit codes so all harnesses run before the job fails.

## Compile tests

**Location:** `tests/compile/`
**Purpose:** Concept conformance and header correctness

Compile tests contain no runtime assertions — they succeed if they compile and
link. They verify:

- `defaults_compile_test.cpp` — `defaults.h` type aliases compile and the
  template instantiations are valid.
- `infra_headers_compile_test.cpp` — infrastructure headers are self-contained
  and compile cleanly in isolation.

Compile tests run as part of the standard build and are included in `ctest`.

## See also

- [local-bus.md](local-bus.md) — LocalPolicy production guide (steady_clock, `run()`)
- [policies.md](policies.md) — MockPolicy unit testing setup
- [custom-policies.md](custom-policies.md) — LocalPolicy concept walkthrough
