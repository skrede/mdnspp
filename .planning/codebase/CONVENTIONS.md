# Coding Conventions

**Analysis Date:** 2026-03-03

## Naming Patterns

**Files:**
- Header files: `.h` extension, PascalCase with underscores for namespaced components (e.g., `record_parser.h`, `mdns_base.h`)
- Implementation files: `.cpp` extension, matching header name
- Include guard format: `MDNSPP_[FILENAME_UPPER]_H` (e.g., `MDNSPP_RECORDS_H`)
- Example: `include/mdnspp/records.h`, `src/mdnspp/records.cpp`

**Classes:**
- PascalCase: `record_parser`, `mdns_base`, `querent`, `observer`, `service_server`
- Type aliases: snake_case with `_t` suffix for data types (e.g., `record_t`, `record_ptr_t`, `query_t`)
- Template parameters: PascalCase (e.g., `T`, `L` for log level)
- Example: `class mdns_base` in `include/mdnspp/mdns_base.h`

**Functions:**
- Member functions: snake_case (e.g., `open_client_sockets()`, `set_log_level()`, `record_parse_ptr()`)
- Free functions: snake_case (e.g., `ip_address_to_string()`, `open_client_sockets()`)
- Getter functions: no prefix, return type in name when relevant (e.g., `address_ipv4()`, `socket_count()`, `record_type_name()`)
- Callback functions: `callback()` for virtual override pattern
- Example: `mdns_base::open_client_sockets()` at line 84 in `src/mdnspp/mdns_base.cpp`

**Variables:**
- Member variables: `m_` prefix with snake_case (e.g., `m_socket_count`, `m_recv_buf_size`, `m_log_sink`, `m_address_ipv4`)
- Static variables: `s_` prefix for file-scoped statics (e.g., `s_test_uuid`, `s_local_app_name`)
- Local variables: snake_case without prefix (e.g., `buffer`, `ret`, `str`, `timeout`)
- Example: `m_socket_count` in `include/mdnspp/mdns_base.h` line 120

**Types/Structs:**
- Struct names: snake_case with `_t` suffix or PascalCase (e.g., `record_t`, `record_ptr_t`, `service_txt`, `query_t`)
- Enum class names: snake_case (e.g., `log_level`)
- Enum values: snake_case (e.g., `log_level::trace`, `log_level::info`)
- Template specialization: preserve naming from parent (e.g., `logger<log_level::info>`)
- Example: `struct record_t` at line 20 in `include/mdnspp/records.h`

## Code Style

**Formatting:**
- No `.clang-format` config in repo root; styles vary based on individual patterns
- Brace placement: opening braces on same line for control structures
- Indentation: 4 spaces (observed in all .cpp and .h files)
- Line length: no strict limit enforced, some lines exceed 100 characters (e.g., line 134 in `include/mdnspp/records.h`)
- Example formatting from `src/mdnspp/mdns_base.cpp` lines 6-14:
```cpp
mdns_base::mdns_base(size_t recv_buf_size)
    : m_socket_count(0)
    , m_socket_limit(32)
    , m_recv_buf_size(recv_buf_size)
    , m_stop{false}
    , m_loglvl(log_level::info)
    , m_sockets(std::make_unique<int[]>(m_socket_limit))
```

**Linting:**
- No eslint/clang-tidy config in root directory
- No style enforcement tool configured in CMakeLists.txt

## Import Organization

**Header Order:**
1. Project headers from `mdnspp/` namespace (e.g., `#include "mdnspp/log.h"`)
2. Standard library headers (e.g., `#include <string>`, `#include <memory>`)
3. Third-party headers without source tree (e.g., `#include <mdns.h>`)
4. Platform-specific headers at end (Windows vs. Unix)

**Pattern Example from `include/mdnspp/mdns_base.h`:**
```cpp
#include "mdnspp/log.h"
#include "mdnspp/logger.h"
#include "mdnspp/mdns_util.h"
#include "mdnspp/record_buffer.h"

#include <atomic>
#include <chrono>
#include <functional>
```

**Namespace Usage:**
- All code in `namespace mdnspp { }` block
- Use `using namespace mdnspp;` at top of .cpp files for implementation
- Example: `src/mdnspp/mdns_base.cpp` line 4: `using namespace mdnspp;`

## Error Handling

**Patterns:**
- Exceptions for unrecoverable conditions: `throw std::runtime_error("message")` in constructors (e.g., `mdns_base.cpp` line 90)
- Return `nullptr` for optional/failed parsing: `record_parser::parse()` returns `nullptr` on unmatched type (line 125 in `src/mdnspp/record_parser.cpp`)
- Return empty containers on parsing failure: `record_parser::parse_txt()` returns empty vector if no TXT records
- Silent failure for logging: logger checks `if(m_sink)` before operations (line 28, 35 in `include/mdnspp/log.h`)
- Example error path from `src/mdnspp/mdns_base.cpp`:
```cpp
if(m_socket_count <= 0)
    throw std::runtime_error("Failed to open any client sockets");
```

## Logging

**Framework:** Custom logger template class `mdnspp::logger<log_level>`

**Patterns:**
- Instantiate per-log with template parameter: `logger<log_level::info> logger(sink)`
- Chain operators for composition: `debug() << "Opened " << m_socket_count << " client socket"`
- Logs formatted in destructor with timestamp prefix: `[level] message`
- Example from `include/mdnspp/log.h` lines 32-38:
```cpp
template<typename T>
std::ostream &operator<<(T v)
{
    if(m_sink)
        m_stream << v;
    return m_stream;
}
```

**Helper functions:**
- `log_level_string(log_level level)` returns string representation ("trace", "debug", "info", "warn", "error")
- Defined in `include/mdnspp/logger.h` lines 22-37

**Usage example from `src/mdnspp/mdns_base.cpp` line 95:**
```cpp
debug() << "Opened " << m_socket_count << " client socket" << (m_socket_count == 1 ? "" : "s");
```

## Comments

**When to Comment:**
- TODO/FIXME markers for incomplete implementations (e.g., `//TODO: Verify` in `src/mdnspp/record_parser.cpp` lines 16, 30)
- Block comments at top of files for attribution (e.g., `/* Adapted from https://github.com/mjansson/mdns/blob/main/mdns.c */` in `include/mdnspp/mdns_util.h` lines 4-5)
- No inline documentation comments observed for typical code flow

**JSDoc/TSDoc:**
- Not used; code relies on function signatures and type declarations for documentation

## Function Design

**Size:**
- Small utility functions: 5-15 lines (e.g., `socket_count()`, `has_address_ipv4()`)
- Parser functions: 10-40 lines (e.g., `record_parse_ptr()`, `record_parse_srv()`)
- Complex operations: up to 100+ lines (e.g., `mdns_base.cpp` listen_while template at lines 60-105, `listen_until_silence()` at lines 46+)

**Parameters:**
- Use named parameter structs for optional configuration: `querent::params` structure with defaults (lines 19-28 in `include/mdnspp/querent.h`)
- Pass immutable references for large objects: `const record_buffer &buffer`
- Use move semantics for ownership transfer: `std::move(sink)`, `std::move(on_response)` in constructors
- Example from `include/mdnspp/querent.h` lines 19-28:
```cpp
struct params
{
    params() : recv_buf_size(2048), send_buf_size(4096), timeout(500) { }
    uint32_t recv_buf_size;
    uint32_t send_buf_size;
    std::chrono::milliseconds timeout;
};
```

**Return Values:**
- `std::shared_ptr<record_t>` for polymorphic record types
- `std::string` for conversions (no string_view)
- `std::optional<sockaddr_in>` for conditional data
- `std::vector<T>` for collections
- `nullptr` for failed optional parsing
- `bool` for predicates and status

## Module Design

**Exports:**
- All public APIs in `include/mdnspp/*.h` files (header-only for templates, implementation .cpp files for classes)
- Public headers listed in CMakeLists.txt `PUBLIC_HEADERS` variable (lines 26-38)
- Private implementation headers in `src/mdnspp/` (e.g., `record_builder.h`)

**Barrel Files:**
- No barrel/index files; each class/component in separate header
- Namespace organization: all files under `mdnspp::` namespace

**Header Organization:**
- Public interface in header, implementation in .cpp
- Template implementations in header file (e.g., `logger` template in `include/mdnspp/log.h`)
- Inline utility functions in headers (e.g., `entry_type_name()`, `record_type_name()` in `include/mdnspp/records.h` lines 96-130)

---

*Convention analysis: 2026-03-03*
