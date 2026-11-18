cmake_minimum_required(VERSION 3.25)
project(mdnspp VERSION 2.1.0)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(MDNSPP_WARNING_FLAGS
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive- /utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wconversion
        -Wsign-conversion
        -Wold-style-cast
        -Wcast-align
        -Woverloaded-virtual
        -Wnon-virtual-dtor
        -Wdouble-promotion
        -Wimplicit-fallthrough
        -Wformat=2
    >
)

option(MDNSPP_BUILD_TESTS "Build the unit and compile test suites" OFF)
option(MDNSPP_BUILD_EXAMPLES "Build example programs" OFF)
option(MDNSPP_BUILD_FUZZ_TESTS "Build fuzz testing targets (requires Clang)" OFF)
option(MDNSPP_CMAKE_FETCH_DEPS "Use CMake FetchContent to download and install dependencies" OFF)
option(MDNSPP_ENABLE_ASIO_POLICY "Build mdnspp-asio adapters (requires asio)" OFF)
option(MDNSPP_ENABLE_ENCRYPT "Build mdnspp-encrypt library with libsodium" OFF)
option(MDNSPP_INSTALL_VENDORED_ASIO "Install the FetchContent-vendored asio header tree into the install prefix (shadows any system asio)" OFF)

include(FetchContent)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

add_subdirectory(lib)

if (MDNSPP_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif ()

if (MDNSPP_BUILD_TESTS OR MDNSPP_BUILD_FUZZ_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif ()
