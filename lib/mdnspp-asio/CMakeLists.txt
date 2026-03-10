if (MDNSPP_FETCH_DEPENDENCIES)
    FetchContent_Declare(
        asio
        GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
        GIT_TAG asio-1-36-0
    )
    FetchContent_MakeAvailable(asio)
else ()
    find_package(asio CONFIG REQUIRED)
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

target_include_directories(mdnspp_asio INTERFACE
    $<BUILD_INTERFACE:${asio_SOURCE_DIR}/asio/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/${INCLUDE_DIRECTORY}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_compile_options(mdnspp_asio INTERFACE
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /utf-8>
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-fPIC -Wall -Wextra>
)

target_link_libraries(mdnspp_asio INTERFACE mdnspp::mdnspp)
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

install(DIRECTORY ${asio_SOURCE_DIR}/asio/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(TARGETS mdnspp_asio EXPORT mdnsppTargets)
