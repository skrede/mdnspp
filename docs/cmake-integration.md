# CMake Integration

## Requirements

- CMake 3.25+
- C++20 compiler:
  - GCC 13+
  - Clang 18+ (Clang 17 has a template argument deduction bug that prevents compilation)
  - MSVC 17+ (Visual Studio 2022)
  - Xcode 15.4+

All exported targets carry `cxx_std_20` in their `INTERFACE_COMPILE_FEATURES`, so consumers do not need to set `CMAKE_CXX_STANDARD` themselves; CMake raises the standard of consuming targets automatically.

## FetchContent

```cmake
cmake_minimum_required(VERSION 3.25)
project(my_app)

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

list(APPEND CMAKE_PREFIX_PATH "/path/to/install")
find_package(mdnspp CONFIG REQUIRED)

add_executable(my_app main.cpp)
target_link_libraries(my_app PRIVATE mdnspp::mdnspp)
```

The installed package supports component checking; requesting a component that the installation does not provide fails at `find_package` time:

```cmake
find_package(mdnspp CONFIG REQUIRED COMPONENTS asio encrypt inproc)
```

Available components: `asio`, `encrypt`, `inproc`, `testing`. The core target `mdnspp::mdnspp` is always present.

### asio and the installed package

`mdnspp::asio` is header-only and the installed package does not bundle ASIO by default. The package config file resolves a system ASIO on a best-effort basis (CMake config package, then header search); otherwise the consumer must provide the ASIO headers through its own include paths. To bundle the FetchContent-vendored ASIO header tree into the install prefix, configure the install with `MDNSPP_INSTALL_VENDORED_ASIO=ON`; note that this installs `asio.hpp` and `asio/` into the prefix's include root, shadowing any ASIO already present there.

### encrypt and the installed package

`mdnspp::encrypt` is installed and exported only when it was built against a system libsodium (`MDNSPP_CMAKE_FETCH_DEPS=OFF`); the package config file then resolves libsodium via `find_dependency` (CMake config package or pkg-config). When built with the FetchContent-vendored libsodium, `mdnspp::encrypt` is available in the build tree (FetchContent/add_subdirectory consumers) but is not installed, because the vendored static `sodium` target cannot be exported.

## CMake Targets

| Target | Description |
|--------|-------------|
| `mdnspp::mdnspp` | default_policy with native sockets, all public headers; links `Threads::Threads`, and `ws2_32`/`iphlpapi` on Windows |
| `mdnspp::asio` | asio_policy + async adapters; built when `MDNSPP_ENABLE_ASIO_POLICY=ON` |
| `mdnspp::encrypt` | encrypted_policy with XChaCha20-Poly1305 transport encryption; built when `MDNSPP_ENABLE_ENCRYPT=ON` (requires libsodium) |
| `mdnspp::inproc` | inproc_policy for in-process multicast simulation and deterministic testing |
| `mdnspp::testing` | mock_policy and test utilities for unit testing without network access |

Target names are identical for FetchContent/add_subdirectory and `find_package` consumers. Most users want `mdnspp::mdnspp`. Add `mdnspp::asio` if you need ASIO completion token support (futures, coroutines, deferred). Link `mdnspp::encrypt` for encrypted transport. Link `mdnspp::inproc` for in-process bus scenarios. Link `mdnspp::testing` in your test targets for mock_policy.

## CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `MDNSPP_ENABLE_ASIO_POLICY` | `OFF` | Build the `mdnspp::asio` adapters (requires ASIO) |
| `MDNSPP_ENABLE_ENCRYPT` | `OFF` | Build the `mdnspp::encrypt` library (requires libsodium) |
| `MDNSPP_CMAKE_FETCH_DEPS` | `OFF` | Use FetchContent to download dependencies (ASIO, libsodium, Catch2) |
| `MDNSPP_INSTALL_VENDORED_ASIO` | `OFF` | Install the FetchContent-vendored ASIO header tree into the install prefix |
| `MDNSPP_BUILD_EXAMPLES` | `OFF` | Build example programs |
| `MDNSPP_BUILD_TESTS` | `OFF` | Build the unit and compile test suites |
| `MDNSPP_BUILD_FUZZ_TESTS` | `OFF` | Build libFuzzer harnesses (requires Clang) |

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

- [Getting Started](getting-started.md) &mdash; Run your first query or service announcement
- [Policies](policies.md) &mdash; Learn about default_policy, asio_policy, and mock_policy
