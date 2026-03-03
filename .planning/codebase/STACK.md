# Technology Stack

**Analysis Date:** 2026-03-03

## Languages

**Primary:**
- C++ C++20 - Core library implementation

**Supporting:**
- CMake - Build configuration and dependency management

## Runtime

**Environment:**
- Cross-platform (Linux, macOS, Windows)

**Build System:**
- CMake 3.20+ - Required minimum version
- Supports multiple generators (Unix Makefiles, Visual Studio, Xcode)

## Frameworks

**Core:**
- mdns (C library) - RFC 6762/6763 compliant mDNS implementation
  - Source: https://github.com/skrede/mdns.git (forked from mjansson/mdns)
  - Fetched via CMake FetchContent from commit 2e0deec
  - Handles networking, packet serialization/deserialization

**Testing:**
- Catch2 3.3.2 - C++ test framework
  - Fetched via CMake FetchContent
  - Used with Catch2::Catch2WithMain

**Build/Dev:**
- CMake FetchContent - Dependency management
- pkg-config - Library detection (Linux/macOS)

## Key Dependencies

**Critical:**
- mdns - Underlying mDNS protocol implementation and socket management
  - Why it matters: Core functionality for service discovery, querying, and DNS record handling

**Standard Library:**
- `<atomic>` - Thread-safe operations for stop flags and log levels
- `<chrono>` - Timeout management and duration handling
- `<functional>` - Callback functions and std::function
- `<format>` - C++20 string formatting for logging
- `<memory>` - Smart pointers (shared_ptr, unique_ptr)
- `<optional>` - Optional values for IPv4/IPv6 addresses
- `<string>` - String handling
- `<vector>` - Dynamic arrays for records and parameters
- `<mutex>` - Thread synchronization in service_server
- `<iostream>` - Standard I/O for default logging
- `<cstdint>` - Fixed-width integer types

## Configuration

**Environment:**
- No environment variables required for normal operation
- Configuration through C++ API: params struct, log sinks, callbacks

**Build:**
- CMakeLists.txt - Main project configuration at `/home/skrede/Workspace/mdnspp/CMakeLists.txt`
- Build options (cmake flags):
  - `MDNSPP_BUILD_TESTS=ON` - Enable test suite
  - `MDNSPP_BUILD_EXAMPLES=ON` - Build example executables
  - `CMAKE_BUILD_TYPE=Release` - For optimized builds

**Platform Detection:**
- Automatic platform detection via CMake
- Windows-specific code paths (WinSock initialization via WSAStartup/WSACleanup in `mdns_base.cpp`)
- Unix/Linux socket APIs used on non-Windows platforms
- Apple-specific timeval handling in `mdns_base.h`

## Platform Requirements

**Development:**
- CMake 3.20+
- C++20 compliant compiler (clang, gcc, MSVC)
- pkg-config (Linux and macOS for dependency discovery)

**Build Targets:**
- Linux (Ubuntu 24.04 tested in CI)
- macOS (14.x tested in CI)
- Windows (2022 tested in CI)

**Runtime:**
- UDP socket support on port 5353 (standard mDNS port)
- Network interface access for multicast operations
- System clock access for TTL/timeout handling

---

*Stack analysis: 2026-03-03*
