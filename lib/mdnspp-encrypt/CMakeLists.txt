if (MDNSPP_CMAKE_FETCH_DEPS)
    include(FetchContent)
    FetchContent_Declare(Sodium
        GIT_REPOSITORY https://github.com/robinlinden/libsodium-cmake.git
        GIT_TAG cfebfd3da486d5a86c644c8b47067e5411c7599c
    )
    set(SODIUM_DISABLE_TESTS ON)
    FetchContent_MakeAvailable(Sodium)
else ()
    find_package(sodium REQUIRED)
endif ()

set(INCLUDE_DIRECTORY include)

add_library(mdnspp_encrypt STATIC
    src/aead.cpp
    src/encrypt_error.cpp
    src/replay_window.cpp
)
add_library(mdnspp::encrypt ALIAS mdnspp_encrypt)

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

install(TARGETS mdnspp_encrypt)
