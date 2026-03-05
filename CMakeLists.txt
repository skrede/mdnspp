cmake_minimum_required(VERSION 3.25)
project(mdnspp)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(Boost_NO_WARN_NEW_VERSIONS ON)

option(MDNSPP_BUILD_TESTS OFF)
option(MDNSPP_BUILD_EXAMPLES OFF)

set(SOURCE_DIRECTORY src)
set(INCLUDE_DIRECTORY include)

set(PUBLIC_HEADERS
    ${INCLUDE_DIRECTORY}/mdnspp/log.h
    ${INCLUDE_DIRECTORY}/mdnspp/logger.h
    ${INCLUDE_DIRECTORY}/mdnspp/querier.h
    ${INCLUDE_DIRECTORY}/mdnspp/records.h
    ${INCLUDE_DIRECTORY}/mdnspp/observer.h
    ${INCLUDE_DIRECTORY}/mdnspp/service_server.h
    ${INCLUDE_DIRECTORY}/mdnspp/service_info.h
    ${INCLUDE_DIRECTORY}/mdnspp/service_discovery.h
    ${INCLUDE_DIRECTORY}/mdnspp/endpoint.h
    ${INCLUDE_DIRECTORY}/mdnspp/mdns_error.h
    ${INCLUDE_DIRECTORY}/mdnspp/policy.h
    ${INCLUDE_DIRECTORY}/mdnspp/parse.h
    ${INCLUDE_DIRECTORY}/mdnspp/testing/mock_policy.h
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
    PUBLIC  ${INCLUDE_DIRECTORY}
    PRIVATE ${SOURCE_DIRECTORY}
)


install(TARGETS mdnspp
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(FILES ${PUBLIC_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp
)

install(FILES
    ${INCLUDE_DIRECTORY}/mdnspp/testing/mock_policy.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp/testing
)

# Optional ASIO policy — fetched only when MDNSPP_ENABLE_ASIO_POLICY=ON
option(MDNSPP_ENABLE_ASIO_POLICY "Build AsioPolicy (AsioSocket, AsioTimer) backed by asio::io_context" OFF)

include(FetchContent)
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

if (MDNSPP_ENABLE_ASIO_POLICY)

    FetchContent_Declare(
        asio
        GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
        GIT_TAG asio-1-36-0
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
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp/asio
    )
endif ()

# Optional NativePolicy — raw UDP multicast, no ASIO dependency
option(MDNSPP_ENABLE_NATIVE_POLICY "Build NativePolicy (NativeSocket, NativeTimer, NativeContext)" OFF)

if (MDNSPP_ENABLE_NATIVE_POLICY)
    add_library(mdnspp_native INTERFACE)
    add_library(mdnspp::native ALIAS mdnspp_native)
    target_include_directories(mdnspp_native INTERFACE ${INCLUDE_DIRECTORY})
    target_link_libraries(mdnspp_native INTERFACE mdnspp)

    if (WIN32)
        target_link_libraries(mdnspp_native INTERFACE ws2_32)
    endif ()

    install(FILES
        ${INCLUDE_DIRECTORY}/mdnspp/native.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp
    )
    install(DIRECTORY ${INCLUDE_DIRECTORY}/mdnspp/native/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp/native
    )
endif ()

install(DIRECTORY ${INCLUDE_DIRECTORY}/mdnspp/detail/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp/detail
)

if (${MDNSPP_BUILD_EXAMPLES})
    add_subdirectory(example)
endif ()

if (${MDNSPP_BUILD_TESTS})
    FetchContent_Declare(
        Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.7.1
    )
    FetchContent_MakeAvailable(Catch2)
    enable_testing()
    add_subdirectory(tests)
endif ()
