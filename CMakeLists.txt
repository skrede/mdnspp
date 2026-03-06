cmake_minimum_required(VERSION 3.25)
project(mdnspp VERSION 2.1.0)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(MDNSPP_BUILD_TESTS OFF)
option(MDNSPP_BUILD_EXAMPLES OFF)

option(MDNSPP_ENABLE_ASIO_POLICY "Build AsioPolicy (AsioSocket, AsioTimer) backed by asio::io_context" OFF)

include(FetchContent)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

add_subdirectory(lib)

if (${MDNSPP_BUILD_EXAMPLES})
    add_subdirectory(example)
endif ()

if (${MDNSPP_BUILD_TESTS})
    enable_testing()
    add_subdirectory(tests)
endif ()
