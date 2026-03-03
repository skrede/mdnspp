# Codebase Structure

**Analysis Date:** 2026-03-03

## Directory Layout

```
mdnspp/
├── include/mdnspp/          # Public API headers
├── src/mdnspp/              # Implementation files
├── tests/                   # Test files
├── example/                 # Usage examples
├── CMakeLists.txt           # Build configuration
├── README.md                # Project documentation
└── .planning/codebase/      # GSD analysis documents (this directory)
```

## Directory Purposes

**include/mdnspp/:**
- Purpose: Public C++ API - all user-facing classes and types
- Contains: Header files (.h)
- Key files:
  - `mdns_base.h` - Base class for all mDNS handlers
  - `service_server.h` - Service announcement and response
  - `service_discovery.h` - Discover services via DNS-SD
  - `querent.h` - Query specific hostnames/services
  - `observer.h` - Passive mDNS traffic monitoring
  - `records.h` - All record type definitions (PTR, SRV, A, AAAA, TXT)
  - `record_parser.h` - Parse raw buffers into typed records
  - `record_buffer.h` - Raw packet metadata wrapper
  - `logger.h`, `log.h` - Logging interface and implementation
  - `mdns_util.h` - Platform-specific socket utilities

**src/mdnspp/:**
- Purpose: Implementation of public API
- Contains: Implementation files (.cpp) and private headers
- Key files:
  - `mdns_base.cpp` - Socket management, listener loops, C library callbacks
  - `service_server.cpp` - Service response handlers for each record type
  - `service_discovery.cpp` - Discovery callback and filtering logic
  - `querent.cpp` - Query sending and response handling
  - `observer.cpp` - Passive observation callback
  - `record_parser.cpp` - Type-specific record parsing
  - `record_builder.h`, `record_builder.cpp` - Construct records for announcements
  - `mdns_util.cpp` - Socket creation and IP address utilities

**tests/:**
- Purpose: Test suite
- Contains: Test files (.cpp) and test headers
- Key files:
  - `log_test.cpp` - Tests for logging subsystem
  - `include/unit_test/` - Test utilities and fixtures

**example/:**
- Purpose: Usage examples demonstrating each major feature
- Contains: Executable examples (.cpp)
- Key files:
  - `serve.cpp` - How to create and serve a service
  - `inquire.cpp` - How to query for services
  - `discover.cpp` - How to discover all services
  - `observe.cpp` - How to observe mDNS traffic passively
  - `log_sink.cpp` - How to implement custom logging

## Key File Locations

**Entry Points:**

- `example/serve.cpp` - Service server usage: creates `service_server`, calls `serve()` with TXT records
- `example/inquire.cpp` - Querent usage: creates `querent`, calls `query()` with query_t
- `example/discover.cpp` - Service discovery usage: creates `service_discovery`, calls `discover()`
- `example/observe.cpp` - Observer usage: creates `observer`, calls `observe()`

**Configuration:**

- `CMakeLists.txt` - Build configuration, dependency management (mdns C library, Catch2 for tests)
  - Options: `MDNSPP_BUILD_TESTS`, `MDNSPP_BUILD_EXAMPLES`
  - Fetches: mjansson/mdns C library via FetchContent
  - Exports: Static library `mdnspp`, alias `mdnspp::mdnspp`

**Core Logic:**

- `include/mdnspp/mdns_base.h` - Abstract base class, socket lifecycle
- `src/mdnspp/mdns_base.cpp` - Socket creation, polling loop, C callback bridge
- `include/mdnspp/service_server.h` - Service definition
- `src/mdnspp/service_server.cpp` - Query handlers, record construction, announcements
- `include/mdnspp/service_discovery.h` - Discovery interface
- `src/mdnspp/service_discovery.cpp` - Discovery sending, callback dispatch

**Record Handling:**

- `include/mdnspp/records.h` - All record type definitions (record_ptr_t, record_srv_t, record_a_t, record_aaaa_t, record_txt_t, record_t base)
  - Also defines operator<< for logging
  - Defines record_filter type alias
- `include/mdnspp/record_parser.h` - Record parsing interface
- `src/mdnspp/record_parser.cpp` - Type-specific parsing logic
- `src/mdnspp/record_builder.h`, `src/mdnspp/record_builder.cpp` - Record construction for responses

**Testing:**

- `tests/log_test.cpp` - Tests for logging system
- `tests/include/unit_test/` - Test fixture or utility headers

## Naming Conventions

**Files:**
- Headers in `include/mdnspp/`: `*.h` with snake_case names
- Implementation in `src/mdnspp/`: `*.cpp` and private `*.h` with snake_case names
- Examples in `example/`: `*.cpp` with action names (serve.cpp, inquire.cpp, discover.cpp, observe.cpp)
- Tests: `*_test.cpp` or `*_spec.cpp`

**Directories:**
- Include directory: `include/mdnspp/`
- Implementation directory: `src/mdnspp/`
- Test directory: `tests/`
- Example directory: `example/`
- Analysis directory: `.planning/codebase/`

**Classes:**
- CamelCase with `_t` suffix for type definitions (e.g., `record_t`, `record_ptr_t`, `service_txt`)
- CamelCase for classes (e.g., `service_server`, `service_discovery`, `querent`, `observer`, `record_parser`, `record_builder`)
- Lowercase with underscores for namespace names (mdnspp)

**Members:**
- Private members: `m_` prefix (e.g., `m_socket_count`, `m_running`, `m_buffer`)
- Type aliases: snake_case (e.g., `socket_t`, `index_t`)

## Where to Add New Code

**New Service Handler (e.g., for NSEC records):**
- Add struct in `include/mdnspp/records.h` (e.g., `record_nsec_t`)
- Add parsing method in `include/mdnspp/record_parser.h` and implement in `src/mdnspp/record_parser.cpp`
- Add builder method in `src/mdnspp/record_builder.h` and implement in `src/mdnspp/record_builder.cpp`
- Add service handler in `src/mdnspp/service_server.cpp` (e.g., `serve_nsec()`)

**New Mutable Operation (e.g., record update without txt):**
- Add public method to service class in `include/mdnspp/service_server.h`
- Implement method in `src/mdnspp/service_server.cpp`
- Update builder if record structure changes

**New Logging Level:**
- Add enum value in `include/mdnspp/logger.h` to `log_level` enum
- Add case to `log_level_string()` function in `include/mdnspp/logger.h`
- Use via `mdns_base::logger<log_level::new_level>()`

**Custom Application Integration:**
- Create custom `log_sink` subclass to inherit from `mdnspp::log_sink`
- Pass shared_ptr to sink to class constructors (e.g., `service_server(instance, service, std::make_shared<my_sink>())`)
- Create custom record filter as lambda or function object, pass to discover/query/observe methods

**Platform-Specific Code:**
- Platform guards already in place using `#ifdef _WIN32` and `#elif defined __APPLE__`
- Socket code in `src/mdnspp/mdns_util.cpp` and `src/mdnspp/mdns_base.cpp`
- Add new platform conditionals following existing pattern

## Special Directories

**cmake-build-debug/:**
- Purpose: CMake build artifacts
- Generated: Yes (by CMake)
- Committed: No (in .gitignore)
- Contains: Intermediate objects, executables, dependency downloads

**include/mdnspp/:**
- Purpose: Public API boundary
- Generated: No
- Committed: Yes
- Contains: Only files users should include - private implementation headers stay in `src/mdnspp/`

**tests/include/unit_test/:**
- Purpose: Shared test utilities
- Generated: No
- Committed: Yes
- Contains: Test fixtures, mock objects (if any)

**.planning/codebase/:**
- Purpose: GSD analysis documents
- Generated: Yes (by GSD agent)
- Committed: Yes
- Contains: ARCHITECTURE.md, STRUCTURE.md, CONVENTIONS.md, TESTING.md, CONCERNS.md

## Import Organization

**Public Headers (user includes):**
```cpp
#include <mdnspp/service_server.h>
#include <mdnspp/records.h>
#include <mdnspp/logger.h>
```

**Implementation Includes (internal):**
```cpp
// In src/mdnspp/*.cpp:
#include "mdnspp/mdns_base.h"      // From include/, relative to src/
#include "mdnspp/record_builder.h"  // Private header, still in mdnspp/ namespace
```

**External Dependencies:**
```cpp
#include <mdns.h>                   // From mjansson/mdns (fetched via CMake)
#include <atomic>                   // Standard library
#include <functional>               // Standard library
#include <winsock2.h>              // Platform-specific (Windows)
#include <netdb.h>                 // Platform-specific (Unix)
```

---

*Structure analysis: 2026-03-03*
