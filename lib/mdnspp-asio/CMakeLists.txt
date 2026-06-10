set(_mdnspp_asio_vendored OFF)

if (MDNSPP_CMAKE_FETCH_DEPS)
    FetchContent_Declare(
        asio
        GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
        GIT_TAG asio-1-36-0
    )
    FetchContent_MakeAvailable(asio)
    add_library(mdnspp_asio_dep INTERFACE)
    target_include_directories(mdnspp_asio_dep SYSTEM INTERFACE
        $<BUILD_INTERFACE:${asio_SOURCE_DIR}/asio/include>
    )
    set(_mdnspp_asio_vendored ON)
elseif (asio_SOURCE_DIR)
    add_library(mdnspp_asio_dep INTERFACE)
    target_include_directories(mdnspp_asio_dep SYSTEM INTERFACE
        $<BUILD_INTERFACE:${asio_SOURCE_DIR}/asio/include>
    )
    set(_mdnspp_asio_vendored ON)
else ()
    find_package(asio CONFIG QUIET)
    if (asio_FOUND AND TARGET asio::asio)
        add_library(mdnspp_asio_dep INTERFACE)
        target_link_libraries(mdnspp_asio_dep INTERFACE asio::asio)
    else ()
        find_package(PkgConfig QUIET)
        if (PkgConfig_FOUND)
            pkg_check_modules(asio_pc QUIET IMPORTED_TARGET asio)
        endif ()
        if (TARGET PkgConfig::asio_pc)
            add_library(mdnspp_asio_dep INTERFACE)
            target_link_libraries(mdnspp_asio_dep INTERFACE PkgConfig::asio_pc)
        else ()
            find_path(ASIO_INCLUDE_DIR
                NAMES asio.hpp
            )
            if (ASIO_INCLUDE_DIR)
                add_library(mdnspp_asio_dep INTERFACE)
                target_include_directories(mdnspp_asio_dep SYSTEM INTERFACE
                    ${ASIO_INCLUDE_DIR}
                )
            else ()
                message(FATAL_ERROR
                    "asio not found. Install asio (system package, vcpkg, conan, "
                    "etc.) or set MDNSPP_CMAKE_FETCH_DEPS=ON to fetch it via "
                    "CMake FetchContent.")
            endif ()
        endif ()
    endif ()
endif ()

set(INCLUDE_DIRECTORY include)

set(PUBLIC_HEADERS
    ${INCLUDE_DIRECTORY}/mdnspp/asio.h
    ${INCLUDE_DIRECTORY}/mdnspp/asio/asio_timer.h
    ${INCLUDE_DIRECTORY}/mdnspp/asio/asio_policy.h
    ${INCLUDE_DIRECTORY}/mdnspp/asio/asio_socket.h
    ${INCLUDE_DIRECTORY}/mdnspp/asio/async_query.h
    ${INCLUDE_DIRECTORY}/mdnspp/asio/async_start.h
    ${INCLUDE_DIRECTORY}/mdnspp/asio/async_observe.h
    ${INCLUDE_DIRECTORY}/mdnspp/asio/async_discover.h
    ${INCLUDE_DIRECTORY}/mdnspp/asio/asio_completion.h
)

add_library(mdnspp_asio INTERFACE)
add_library(mdnspp::asio ALIAS mdnspp_asio)

target_compile_features(mdnspp_asio INTERFACE cxx_std_20)

target_include_directories(mdnspp_asio INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/${INCLUDE_DIRECTORY}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(mdnspp_asio INTERFACE
    mdnspp::mdnspp
    $<BUILD_INTERFACE:mdnspp_asio_dep>
)
target_compile_definitions(mdnspp_asio INTERFACE
    MDNSPP_ENABLE_ASIO_POLICY
    $<$<PLATFORM_ID:Windows>:_WIN32_WINNT=0x0601>
)

install(FILES ${PUBLIC_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp/asio
)

install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/${INCLUDE_DIRECTORY}/mdnspp/asio.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp
)

if (_mdnspp_asio_vendored)
    install(DIRECTORY ${asio_SOURCE_DIR}/asio/include/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )
endif ()

install(TARGETS mdnspp_asio EXPORT mdnsppTargets)
