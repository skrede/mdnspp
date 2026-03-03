# Testing Patterns

**Analysis Date:** 2026-03-03

## Test Framework

**Runner:**
- Catch2 v3.3.2
- Config: `CMakeLists.txt` lines 72-80
- Fetched via FetchContent during CMake configure
- Tests require `MDNSPP_BUILD_TESTS ON` flag

**Assertion Library:**
- Catch2's built-in assertions: `CHECK()`, `REQUIRE()`

**Run Commands:**
```bash
cmake -B build -DMDNSPP_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build
```

## Test File Organization

**Location:**
- Co-located strategy: tests in `/home/skrede/Workspace/mdnspp/tests/` directory separate from source
- Test resources: `tests/resources/` directory (referenced as `UNIT_TEST_RESOURCE_DIR` in CMakeLists.txt line 1)
- Test headers: `tests/include/unit_test/` directory

**Naming:**
- Test files: `{component}_test.cpp` pattern (e.g., `log_test.cpp`)
- Test executable names match test file base name (CMakeLists.txt `make_test()` function uses `TEST_FILE` as executable name)

**Structure:**
```
tests/
├── CMakeLists.txt          # Test build configuration
├── log_test.cpp            # Log system tests
├── include/
│   └── unit_test/
│       └── autonomos_unittest_state.h  # Test utilities/fixtures
└── resources/              # Test data directory
```

## Test Structure

**Suite Organization:**
```cpp
// From tests/log_test.cpp
TEST_CASE("message log")
{
    {
        mdnspp::logger<mdnspp::log_level::info> logger(std::make_shared<mdnspp::log_sink_f<set_output>>());
        logger << "This is a message";
    }
    CHECK(test_output == std::format("[{}] This is a message", log_level_string(mdnspp::log_level::info)));
}
```

**Patterns:**
- One `TEST_CASE()` per test name string
- Scope-based setup/teardown: objects destroyed at end of block (line 16-19 in `log_test.cpp`)
- Assertions with `CHECK()` macro for non-fatal failures
- File-scoped static setup: `std::string test_output;` and `void set_output(const std::string &str)` helper (lines 7-12 in `log_test.cpp`)

## Mocking

**Framework:**
- No dedicated mocking library detected (e.g., no GoogleMock, gmock, or catch2-gsl imports)
- Manual mocking through function pointers and custom sinks

**Patterns:**
```cpp
// Functional sink pattern for testing - from log_test.cpp
std::string test_output;

void set_output(const std::string &str)
{
    test_output = str;
}

// Passed to logger as:
mdnspp::logger<mdnspp::log_level::info> logger(std::make_shared<mdnspp::log_sink_f<set_output>>());
```

**What to Mock:**
- I/O operations: use custom `log_sink` implementations instead of console output
- Callback functions: pass `std::function` to capture/test behavior

**What NOT to Mock:**
- Core record parsing: unit tests exercise actual parsing logic
- Socket operations would be complex; tests focus on data transformation layers

## Fixtures and Factories

**Test Data:**
```cpp
// From tests/include/unit_test/autonomos_unittest_state.h
inline void initializeTestState(bool noexcepts = true)
{
    State::setLogger(std::make_shared<spdlog::logger>("AutonomOS"));
    State::setNoexcepts(noexcepts);
    State::setApplicationId(s_test_uuid);
    State::setApplicationName(s_local_app_name);
}
```

**Location:**
- `tests/include/unit_test/` for shared test utilities and fixtures
- File-scoped statics in test files for test-specific data (e.g., `test_output` in `log_test.cpp`)
- Initialization helpers available in fixture header

## Coverage

**Requirements:**
- Not enforced; no coverage configuration in CMakeLists.txt or build system

**View Coverage:**
- Not configured; would require additional CMake options (e.g., `--coverage` flag or Gcov setup)

## Test Types

**Unit Tests:**
- Scope: Single-component functionality (e.g., logging output format, record type name conversion)
- Approach: Direct instantiation and call, verify output against expected values
- Example: `log_test.cpp` tests logger output formatting by comparing string result
- Files: `tests/log_test.cpp`

**Integration Tests:**
- Not implemented; no tests for socket communication, mDNS query/response cycles, or service discovery

**E2E Tests:**
- Not used; architecture requires manual testing with live mDNS traffic or socket simulation

## Common Patterns

**Async Testing:**
```cpp
// Pattern not observed
// Logger uses scope-based cleanup (destructor triggers log() call)
// No std::thread or async function testing framework present
```

**Error Testing:**
```cpp
// Pattern not observed in log_test.cpp
// Catch2 provides REQUIRE_THROWS() for exception testing
// No exception tests visible in existing test suite
```

**Typical Test Pattern from log_test.cpp:**
```cpp
TEST_CASE("message log")
{
    // Setup: Create objects needed for test
    {
        mdnspp::logger<mdnspp::log_level::info> logger(
            std::make_shared<mdnspp::log_sink_f<set_output>>()
        );
        // Act: Perform operation
        logger << "This is a message";
        // Implicit teardown: logger destroyed at scope end
    }
    // Assert: Check results
    CHECK(test_output == std::format("[{}] This is a message",
                                     log_level_string(mdnspp::log_level::info)));
}
```

## Test Build Configuration

**CMake Function:** `make_test()` helper (lines 5-10 in `tests/CMakeLists.txt`)
```cmake
function(make_test TEST_FILE)
    add_executable(${TEST_FILE} "${TEST_FILE}.cpp")
    target_link_libraries(${TEST_FILE} PRIVATE mdnspp Catch2::Catch2WithMain)
    target_include_directories(${TEST_FILE} PRIVATE ${MDNSPP_SOURCE_DIR} ${UNIT_TEST_INCLUDE})
    add_test(NAME ${TEST_FILE} COMMAND ${TEST_FILE})
endfunction()

make_test(log_test)
```

**Key Details:**
- Each test file compiled as standalone executable
- Links against `mdnspp` library and `Catch2::Catch2WithMain` (provides main entry point)
- Tests have access to private source directory `src/mdnspp/` via target_include_directories
- Tests registered with CTest via `add_test()` for `ctest` runner

## Test Entry Points

**Main Test Runner:**
- Catch2::Catch2WithMain provides default main() for test executables
- No custom main entry point in test code
- Tests discovered and executed automatically by Catch2

**CMake Integration:**
- `enable_testing()` called in root CMakeLists.txt line 78
- Tests run via `ctest` after build: `ctest --test-dir build`

## Test Coverage Analysis

**Current Coverage:**
- `log_test.cpp`: Single test case covering logger output formatting
- `MDNSPP_BUILD_TESTS` disabled by default (line 8 in CMakeLists.txt): `option(MDNSPP_BUILD_TESTS OFF)`
- Record parsing, querying, service discovery: **untested** - no test files for these major components

**Test Gap Areas:**
- `record_parser.cpp` (212 lines, 1 TODO): No tests for PTR, SRV, A, AAAA, TXT record parsing
- `mdns_base.cpp` (518 lines): No tests for socket management, listen loop, callback handling
- `querent.cpp` (146 lines): No tests for query execution, response filtering
- `observer.cpp` (94 lines): No tests for service observation, filter application
- `service_server.cpp` (305 lines): No tests for service advertisement
- `record_builder.cpp` (275 lines): No tests for record construction

---

*Testing analysis: 2026-03-03*
