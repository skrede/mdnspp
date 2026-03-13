cmake_minimum_required(VERSION 3.25)
project(mdnspp VERSION 2.1.0)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_VERBOSE_MAKEFILE ON)

set(MDNSPP_WARNING_FLAGS
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /permissive- /utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:
        -fPIC
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

option(MDNSPP_BUILD_TESTS OFF)
option(MDNSPP_BUILD_EXAMPLES OFF)
option(MDNSPP_BUILD_FUZZ_TESTS "Build fuzz testing targets (requires Clang)" OFF)

option(MDNSPP_CMAKE_FETCH_DEPS "Use CMake FetchContent to download and install dependencies" OFF)
option(MDNSPP_ENABLE_ASIO_POLICY "Build AsioPolicy (AsioSocket, AsioTimer) backed by asio::io_context" OFF)

include(FetchContent)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

add_subdirectory(lib)

if (${MDNSPP_BUILD_EXAMPLES})
    add_subdirectory(examples)
endif ()

if (MDNSPP_BUILD_TESTS OR MDNSPP_BUILD_FUZZ_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif ()
