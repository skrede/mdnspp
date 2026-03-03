cmake_minimum_required(VERSION 3.25)
project(mdnspp)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(Boost_NO_WARN_NEW_VERSIONS ON)

option(MDNSPP_BUILD_TESTS OFF)
option(MDNSPP_BUILD_EXAMPLES OFF)

include(FetchContent)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

find_path(MDNS_INCLUDE_DIRS "mdns.h")
if(NOT MDNS_INCLUDE_DIRS_FOUND)
    FetchContent_Declare(mdns
        GIT_REPOSITORY https://github.com/skrede/mdns.git
        GIT_TAG        2e0deec08c5e1cb97f5baf4e6f47f4fc1be4be49)
    FetchContent_MakeAvailable(mdns)
endif()

set(SOURCE_DIRECTORY src)
set(INCLUDE_DIRECTORY include)

set(PUBLIC_HEADERS
    ${INCLUDE_DIRECTORY}/mdnspp/log.h
    ${INCLUDE_DIRECTORY}/mdnspp/logger.h
    ${INCLUDE_DIRECTORY}/mdnspp/querent.h
    ${INCLUDE_DIRECTORY}/mdnspp/records.h
    ${INCLUDE_DIRECTORY}/mdnspp/observer.h
    ${INCLUDE_DIRECTORY}/mdnspp/mdns_base.h
    ${INCLUDE_DIRECTORY}/mdnspp/record_buffer.h
    ${INCLUDE_DIRECTORY}/mdnspp/service_server.h
    ${INCLUDE_DIRECTORY}/mdnspp/service_discovery.h
    ${INCLUDE_DIRECTORY}/mdnspp/endpoint.h
    ${INCLUDE_DIRECTORY}/mdnspp/mdns_error.h
    ${INCLUDE_DIRECTORY}/mdnspp/socket_policy.h
    ${INCLUDE_DIRECTORY}/mdnspp/testing/mock_socket_policy.h
)

set(CORE_SOURCES
    ${SOURCE_DIRECTORY}/mdnspp/mdns_util.cpp
    ${SOURCE_DIRECTORY}/mdnspp/mdns_base.cpp
    ${SOURCE_DIRECTORY}/mdnspp/record_buffer.cpp
    ${SOURCE_DIRECTORY}/mdnspp/record_parser.cpp
    ${SOURCE_DIRECTORY}/mdnspp/record_builder.h
    ${SOURCE_DIRECTORY}/mdnspp/record_builder.cpp
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

target_link_libraries(mdnspp PUBLIC mdns)

install(TARGETS mdnspp
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(FILES ${PUBLIC_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp
)

install(FILES ${INCLUDE_DIRECTORY}/mdnspp/testing/mock_socket_policy.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp/testing
)

if(${MDNSPP_BUILD_EXAMPLES})
    add_subdirectory(example)
endif()

if(${MDNSPP_BUILD_TESTS})
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.7.1
    )
    FetchContent_MakeAvailable(Catch2)
    enable_testing()
    add_subdirectory(tests)
endif()
