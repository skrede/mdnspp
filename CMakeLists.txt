cmake_minimum_required(VERSION 3.15)
project(mdnspp)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(Boost_NO_WARN_NEW_VERSIONS ON)

option(MDNSPP_BUILD_TESTS OFF)
option(MDNSPP_BUILD_EXAMPLES OFF)

include(FetchContent)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

find_path(MDNS_INCLUDE_DIRS "mdns.h")
if(NOT MDNS_INCLUDE_DIRS_FOUND)
    FetchContent_Declare(mdns
        GIT_REPOSITORY https://github.com/mjansson/mdns.git
        GIT_TAG        23c6f01bb8c68e0e9f6c1ee17b7ae721344925ab)
    FetchContent_MakeAvailable(mdns)
endif()

FetchContent_Declare(fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG 937b7c5c10dadee2913b548041551828e7934eb7
)
FetchContent_MakeAvailable(fmt)

set(SOURCE_DIRECTORY src)
set(INCLUDE_DIRECTORY include)

set(PUBLIC_HEADERS
    ${INCLUDE_DIRECTORY}/mdnspp/log.h
    ${INCLUDE_DIRECTORY}/mdnspp/logger.h
    ${INCLUDE_DIRECTORY}/mdnspp/querier.h
    ${INCLUDE_DIRECTORY}/mdnspp/records.h
    ${INCLUDE_DIRECTORY}/mdnspp/observer.h
    ${INCLUDE_DIRECTORY}/mdnspp/mdns_util.h
    ${INCLUDE_DIRECTORY}/mdnspp/mdns_base.h
    ${INCLUDE_DIRECTORY}/mdnspp/service_server.h
    ${INCLUDE_DIRECTORY}/mdnspp/message_buffer.h
    ${INCLUDE_DIRECTORY}/mdnspp/message_parser.h
    ${INCLUDE_DIRECTORY}/mdnspp/service_discovery.h
)

set(CORE_SOURCES
    ${SOURCE_DIRECTORY}/mdnspp/querier.cpp
    ${SOURCE_DIRECTORY}/mdnspp/observer.cpp
    ${SOURCE_DIRECTORY}/mdnspp/mdns_util.cpp
    ${SOURCE_DIRECTORY}/mdnspp/mdns_base.cpp
    ${SOURCE_DIRECTORY}/mdnspp/service_server.cpp
    ${SOURCE_DIRECTORY}/mdnspp/message_buffer.cpp
    ${SOURCE_DIRECTORY}/mdnspp/message_parser.cpp
    ${SOURCE_DIRECTORY}/mdnspp/record_builder.h
    ${SOURCE_DIRECTORY}/mdnspp/record_builder.cpp
    ${SOURCE_DIRECTORY}/mdnspp/service_discovery.cpp
)

add_library(mdnspp STATIC
    ${PUBLIC_HEADERS}
    ${CORE_SOURCES}
)

add_library(mdnspp::mdnspp ALIAS mdnspp)

target_include_directories(mdnspp
    PUBLIC ${INCLUDE_DIRECTORY}
    PRIVATE ${SOURCE_DIRECTORY}
)

target_link_libraries(mdnspp PUBLIC mdns fmt::fmt)

if(${MDNSPP_BUILD_EXAMPLES})
    add_subdirectory(example)
endif()

if(${MDNSPP_BUILD_TESTS})
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.3.2
    )
    FetchContent_MakeAvailable(Catch2)
    enable_testing()
    add_subdirectory(tests)
endif()
