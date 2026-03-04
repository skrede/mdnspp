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
    ${INCLUDE_DIRECTORY}/mdnspp/service_server.h
    ${INCLUDE_DIRECTORY}/mdnspp/service_info.h
    ${INCLUDE_DIRECTORY}/mdnspp/service_discovery.h
    ${INCLUDE_DIRECTORY}/mdnspp/endpoint.h
    ${INCLUDE_DIRECTORY}/mdnspp/mdns_error.h
    ${INCLUDE_DIRECTORY}/mdnspp/policy.h
    ${INCLUDE_DIRECTORY}/mdnspp/socket_policy.h
    ${INCLUDE_DIRECTORY}/mdnspp/timer_policy.h
    ${INCLUDE_DIRECTORY}/mdnspp/parse.h
    ${INCLUDE_DIRECTORY}/mdnspp/testing/mock_policy.h
    ${INCLUDE_DIRECTORY}/mdnspp/testing/mock_socket_policy.h
    ${INCLUDE_DIRECTORY}/mdnspp/testing/mock_timer_policy.h
)

set(CORE_SOURCES
    ${SOURCE_DIRECTORY}/mdnspp/mdns_util.cpp
    ${SOURCE_DIRECTORY}/mdnspp/parse.cpp
)

add_library(mdnspp STATIC
    ${PUBLIC_HEADERS}
    ${CORE_SOURCES}
)

add_library(mdnspp::mdnspp ALIAS mdnspp)

target_include_directories(mdnspp
    PUBLIC ${INCLUDE_DIRECTORY} ${SOURCE_DIRECTORY}
)

target_link_libraries(mdnspp PUBLIC mdns)

install(TARGETS mdnspp
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(FILES ${PUBLIC_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp
)

install(FILES
    ${INCLUDE_DIRECTORY}/mdnspp/testing/mock_policy.h
    ${INCLUDE_DIRECTORY}/mdnspp/testing/mock_socket_policy.h
    ${INCLUDE_DIRECTORY}/mdnspp/testing/mock_timer_policy.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp/testing
)

# Optional ASIO policy — fetched only when MDNSPP_ENABLE_ASIO_POLICY=ON
option(MDNSPP_ENABLE_ASIO_POLICY "Build AsioSocketPolicy and AsioTimerPolicy (requires network at configure time)" OFF)

if(MDNSPP_ENABLE_ASIO_POLICY)
    FetchContent_Declare(
        asio
        GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
        GIT_TAG        asio-1-36-0
    )
    FetchContent_MakeAvailable(asio)

    add_library(mdnspp_asio INTERFACE)
    add_library(mdnspp::asio ALIAS mdnspp_asio)
    target_include_directories(mdnspp_asio INTERFACE
        ${asio_SOURCE_DIR}/asio/include
        ${INCLUDE_DIRECTORY}
    )
    target_compile_definitions(mdnspp_asio INTERFACE
        ASIO_STANDALONE
    )
    target_link_libraries(mdnspp_asio INTERFACE mdnspp)

    install(FILES
        ${INCLUDE_DIRECTORY}/mdnspp/asio/asio_policy.h
        ${INCLUDE_DIRECTORY}/mdnspp/asio/asio_socket.h
        ${INCLUDE_DIRECTORY}/mdnspp/asio/asio_timer.h
        ${INCLUDE_DIRECTORY}/mdnspp/asio/asio_socket_policy.h
        ${INCLUDE_DIRECTORY}/mdnspp/asio/asio_timer_policy.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp/asio
    )
endif()

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
