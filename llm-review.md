# mdnspp Project Review

This is an objective, critical, and rigorous software engineering review of **mdnspp**, a C++23 mDNS/DNS-SD library.

## a) Code Quality & Architecture
**The Good:**
The architectural decision to use a **policy-based design** (`template <Policy P> class basic_service_server`) is the strongest aspect of this library. By decoupling the execution environment (executor, socket, timer) from the protocol logic at compile time, it successfully avoids the "hidden thread" anti-pattern prevalent in other mDNS libraries (like microdns or mdnsd). The usage of modern C++ features (`std::move_only_function`, `std::span`, `std::expected` idioms via error codes, concepts, and strict bounds checking) leads to highly expressive code.

The RFC compliance layer is now substantial. Query backoff (RFC 6762 §5.2), duplicate answer suppression (§7.4), TC-bit accumulation (§6), cache-flush propagation (§10.2), and probing/announcing (§8) are each implemented as focused, composable `detail/` headers with dedicated test files. The compliance matrix in `docs/rfc/README.md` reports 28 of 31 tracked clauses implemented — a credible ratio for a library at this stage.

The addition of `basic_service_monitor` as a high-level continuous discovery façade, composing `query_backoff`, `ttl_refresh`, `duplicate_answer_suppression`, and `record_cache` internally, is a well-executed example of the policy architecture paying dividends: the monitor inherits ASIO or standalone networking for free via the same template parameter.

**The Bad:**
- **C++23 Requirement:** Mandating C++23 remains an adoption blocker. The primary target audience for a dependency-free, thread-less mDNS library is IoT, embedded systems, and game engines. Many of these toolchains are stuck on C++14 or C++17. By forcing C++23, `mdnspp` excludes a segment of its most logical user base. That said, on desktop and server platforms (the library's current sweet spot), C++23 support in GCC 13+, Clang 17+, and MSVC 17.7+ is now broadly available, which weakens this criticism compared to a year ago.
- **Security Posture (Missing Fuzzing):** The project implements a custom DNS wire format parser (`detail/dns_read.h`, `parse.h`). Custom network protocol parsers written in C++ are notorious vectors for CVEs (buffer over-reads, infinite loops via malicious DNS label compression pointers). There is still **zero fuzz testing** (no libFuzzer or AFL integration). The parser code is reasonably guarded by bounds checks and `std::span`, but absence of a fuzz harness means confidence in adversarial robustness is asserted, not demonstrated.

## b) Coverage
**The Good:**
The test suite has grown considerably — 36 test files covering unit, integration, and conformance dimensions. RFC compliance features each have dedicated test files (`query_backoff_test.cpp`, `duplicate_answer_suppression_test.cpp`, `tc_accumulator_test.cpp`, `ttl_refresh_test.cpp`, `server_known_answer_test.cpp`, `server_probe_announce_test.cpp`). Policy conformance tests (`asio_conformance_test.cpp`, `concept_conformance_test.cpp`, `default_conformance_test.cpp`) verify that each policy satisfies the required concepts at compile time. The CI pipeline enforces coverage tracking via Codecov across Linux, macOS, and Windows.

**The Bad:**
- **No fuzz testing.** This remains the single most critical gap. A network-facing C++ parser without a fuzz corpus is a latent liability.
- **No benchmarks.** For a library whose policy architecture is predicated on zero-overhead abstraction, there are no microbenchmarks validating parser throughput, allocation profile under multicast storms, or policy dispatch overhead. Catch2 has built-in `BENCHMARK()` support that would be trivial to wire up.

## c) Documentation
**The Good:**
Documentation has been comprehensively restructured and expanded. The `docs/` directory now contains:
- **9 usage guides** covering getting-started, policies, socket options, async patterns, mDNS options, custom policies, CMake integration, service monitor, and record cache.
- **14 API reference pages** in `docs/api/`, one per public type — each with constructor signatures, method tables, and cross-references.
- **10 RFC compliance pages** in `docs/rfc/`, each following a standardized four-section format (Example, Compliance Status, In-Depth, See Also), plus a master compliance checklist in `docs/rfc/README.md` that matrices out 31 clauses across RFC 6762 and RFC 6763.
- A categorized index at `docs/README.md` tying everything together.

The documentation is no longer merely transparent about gaps — it now backs up most claims with dedicated guide pages and working code examples.

**The Bad:**
The documentation, while extensive in breadth, is sometimes LLM-flavored in tone — slightly verbose and pattern-repetitive across pages. A human editing pass would tighten the prose. More substantively, the custom-policies guide describes *what* the concept requirements are but could benefit from a complete, minimal, working custom policy example compiled end-to-end (beyond the conceptual sketch).

## d) Examples
**The Good:**
The `examples/` directory has been reorganized into per-type subfolders and expanded to **18 programs** across 6 categories:
- `observer/` (2): basic, ASIO callback
- `querier/` (2): basic, ASIO callback
- `service_discovery/` (3): basic, subtype filtering, ASIO callback
- `service_server/` (4): basic, multi-service, conflict resolution, ASIO startup
- `service_monitor/` (4): basic, custom multicast group, ASIO callback, observe mode
- `record_cache/` (2): standalone, promiscuous

The custom multicast group example (`service_monitor/02_custom_group.cpp`) directly addresses the previous gap: it shows how to run discovery on an isolated network namespace with a private group address. The ASIO examples now demonstrate standalone `io_context` integration in several contexts.

**The Bad:**
The examples still target two execution models: `DefaultPolicy` (blocking) and `AsioPolicy` (ASIO event loop). There is no example of a truly custom policy — say, a mock policy for unit testing, or a game-loop tick-driven policy — which remains the architecturally interesting case. The `custom-policies` guide describes the concept requirements, but a compilable `examples/custom_policy/` directory would bridge the gap between documentation and practice.

## e) Novelty & "Worth It" Factor
Is this "yet another framework"? **No longer — it has grown into a credible, narrowly-scoped alternative.**

### Comparison to Alternatives
1. **System Daemons (Avahi/Bonjour):** The RFC compliance gap has narrowed substantially. With query backoff, duplicate suppression, TC-bit handling, cache-flush propagation, and probing/announcing all implemented, `mdnspp` now covers the clauses that matter most for well-behaved multicast traffic. It still lacks a few edge-case clauses (legacy unicast, simultaneous probe tiebreaking), but for typical service discovery workflows it is now a viable alternative that avoids the deployment complexity of a system daemon.
2. **Heavyweight Frameworks (Poco / Qt):** `mdnspp` continues to dominate here for lightweight applications — no 50MB framework dependency, no hidden threads, no runtime configuration.
3. **C-Libraries (mdnsd):** This remains `mdnspp`'s real competition. C-libraries are universally portable and battle-tested. `mdnspp` offers a safer, more ergonomic, and significantly more feature-complete API (continuous monitoring, TTL-aware caching, policy-based async), but loses on compiler compatibility. The addition of `service_monitor` — a high-level continuous discovery component with automatic backoff and loss detection — is functionality that most C alternatives leave to the application author.

### Conclusion
`mdnspp` has matured from a promising skeleton into a **feature-complete mDNS/DNS-SD library for modern C++ environments**. The policy-based architecture has proven its worth: `basic_service_monitor` composes half a dozen RFC compliance mechanisms and inherits ASIO or standalone networking with zero code duplication. Documentation is comprehensive. Examples are practical.

Two gaps remain before it can be recommended for production use without caveats:
1. **Fuzz testing for the DNS parser.** This is non-negotiable for a network-facing C++ parser. A libFuzzer harness targeting `parse.h` and `dns_read.h` would be a small investment with outsized confidence gains.
2. **Benchmarks.** The zero-overhead claim is architecturally plausible but empirically unverified. Even a handful of Catch2 `BENCHMARK()` tests measuring parser throughput and policy dispatch overhead would substantiate the design rationale.

The C++23 requirement, while still limiting for embedded toolchains, is increasingly reasonable on the desktop/server platforms where `mdnspp` is most naturally deployed.
