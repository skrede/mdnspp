if (MDNSPP_CMAKE_FETCH_DEPS)
    include(FetchContent)
    FetchContent_Declare(Sodium
        GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
        GIT_TAG cfebfd3da486d5a86c644c8b47067e5411c7599c
    )
    set(SODIUM_DISABLE_TESTS ON)
    FetchContent_MakeAvailable(Sodium)
    set(_mdnspp_sodium_provider "vendored")
else ()
    find_package(sodium QUIET)
    if (sodium_FOUND)
        set(_mdnspp_sodium_provider "config")
    else ()
        find_package(PkgConfig QUIET)
        if (PkgConfig_FOUND)
            pkg_check_modules(sodium REQUIRED IMPORTED_TARGET libsodium)
            add_library(sodium ALIAS PkgConfig::sodium)
            set(_mdnspp_sodium_provider "pkgconfig")
        else ()
            message(FATAL_ERROR "libsodium not found. Install libsodium-dev or set MDNSPP_CMAKE_FETCH_DEPS=ON")
        endif ()
    endif ()
endif ()

set(INCLUDE_DIRECTORY include)

add_library(mdnspp_encrypt STATIC
    src/aead.cpp
    src/encrypt_error.cpp
    src/replay_window.cpp
)
add_library(mdnspp::encrypt ALIAS mdnspp_encrypt)
set_target_properties(mdnspp_encrypt PROPERTIES EXPORT_NAME encrypt)

target_compile_features(mdnspp_encrypt PUBLIC cxx_std_20)

target_include_directories(mdnspp_encrypt PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/${INCLUDE_DIRECTORY}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(mdnspp_encrypt
    PUBLIC mdnspp
    PRIVATE sodium
)

target_compile_options(mdnspp_encrypt PRIVATE ${MDNSPP_WARNING_FLAGS})

install(DIRECTORY ${INCLUDE_DIRECTORY}/mdnspp/encrypt/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp/encrypt
)

if (_mdnspp_sodium_provider STREQUAL "vendored")
    # The FetchContent libsodium wrapper builds a non-exportable static
    # `sodium` target from source; an installed mdnspp_encrypt would carry a
    # dangling reference to it. Installation of mdnspp::encrypt therefore
    # requires a system libsodium (MDNSPP_CMAKE_FETCH_DEPS=OFF).
    message(STATUS
        "mdnspp: mdnspp::encrypt is built against the vendored libsodium and "
        "is not installed or exported; build with MDNSPP_CMAKE_FETCH_DEPS=OFF "
        "against a system libsodium to install mdnspp::encrypt.")
else ()
    install(TARGETS mdnspp_encrypt EXPORT mdnsppTargets)
    set(MDNSPP_ENCRYPT_EXPORTED ON PARENT_SCOPE)
    set(MDNSPP_ENCRYPT_SODIUM_PROVIDER "${_mdnspp_sodium_provider}" PARENT_SCOPE)
endif ()
