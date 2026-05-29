# CMake Integration

## Requirements

- CMake 3.25+
- C++23 compiler:
  - GCC 13+
  - Clang 18+ (Clang 17 has a template argument deduction bug that prevents compilation)
  - MSVC 17+ (Visual Studio 2022) with `/std:c++latest`
  - Xcode 15.4+

## FetchContent

```cmake
cmake_minimum_required(VERSION 3.25)
project(my_app)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(
    mdnspp
    GIT_REPOSITORY https://github.com/skrede/mdnspp.git
    GIT_TAG        master  # pin to a specific commit hash for reproducibility
)
FetchContent_MakeAvailable(mdnspp)

add_executable(my_app main.cpp)
target_link_libraries(my_app PRIVATE mdnspp::mdnspp)
```

Link against `mdnspp::mdnspp` for standalone usage with the default policy, or `mdnspp::asio` for ASIO completion token support. The `mdnspp::asio` target is built when `MDNSPP_ENABLE_ASIO_POLICY=ON`; ASIO is then discovered from the system (CMake config, pkg-config, or header search) or, if `MDNSPP_CMAKE_FETCH_DEPS=ON`, fetched via FetchContent.

## find_package

First, build and install mdnspp:

```bash
git clone https://github.com/skrede/mdnspp.git
cmake -B build -S mdnspp -DCMAKE_BUILD_TYPE=Release
cmake --build build
cmake --install build --prefix /path/to/install
```

Then consume with `find_package`:

```cmake
cmake_minimum_required(VERSION 3.25)
project(my_app)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

list(APPEND CMAKE_PREFIX_PATH "/path/to/install")
find_package(mdnspp CONFIG REQUIRED)

add_executable(my_app main.cpp)
target_link_libraries(my_app PRIVATE mdnspp::mdnspp)
```

## CMake Targets

| Target | Description |
|--------|-------------|
| `mdnspp::mdnspp` | DefaultPolicy with native sockets, all public headers; links `ws2_32` on Windows |
| `mdnspp::asio` | AsioPolicy + async adapters; built when `MDNSPP_ENABLE_ASIO_POLICY=ON` |
| `mdnspp::inproc` | InProcPolicy for in-process multicast simulation and deterministic testing |
| `mdnspp::testing` | MockPolicy and test utilities for unit testing without network access |

Most users want `mdnspp::mdnspp`. Add `mdnspp::asio` if you need ASIO completion token support (futures, coroutines, deferred). Link `mdnspp::inproc` for in-process bus scenarios. Link `mdnspp::testing` in your test targets for MockPolicy.

## CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `MDNSPP_ENABLE_ASIO_POLICY` | `OFF` | Build the `mdnspp::asio` adapters (requires ASIO) |
| `MDNSPP_ENABLE_ENCRYPT` | `OFF` | Build the `mdnspp::encrypt` library (requires libsodium) |
| `MDNSPP_CMAKE_FETCH_DEPS` | `OFF` | Use FetchContent to download dependencies (ASIO, libsodium, Catch2) |
| `MDNSPP_BUILD_EXAMPLES` | `OFF` | Build example programs |
| `MDNSPP_BUILD_TESTS` | `OFF` | Build test suite |

`MDNSPP_ENABLE_ASIO_POLICY` and `MDNSPP_CMAKE_FETCH_DEPS` are orthogonal: the first turns the ASIO adapters on, the second decides where ASIO comes from. With `MDNSPP_ENABLE_ASIO_POLICY=ON` and `MDNSPP_CMAKE_FETCH_DEPS=OFF`, ASIO is discovered from the system (CMake config, pkg-config, or header lookup, in that order); with both `ON`, ASIO is fetched via FetchContent.

## Building from Source

```bash
git clone https://github.com/skrede/mdnspp.git
cd mdnspp

cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cmake --install build --prefix install
```

To also build examples and tests:

```bash
cmake -B build \
    -DCMAKE_BUILD_TYPE=Release \
    -DMDNSPP_BUILD_EXAMPLES=ON \
    -DMDNSPP_BUILD_TESTS=ON \
    -DMDNSPP_ENABLE_ASIO_POLICY=ON \
    -DMDNSPP_CMAKE_FETCH_DEPS=ON
cmake --build build
ctest --test-dir build
```

## Next Steps

- [Getting Started](getting-started.md) -- Run your first query or service announcement
- [Policies](policies.md) -- Learn about DefaultPolicy, AsioPolicy, and MockPolicy
