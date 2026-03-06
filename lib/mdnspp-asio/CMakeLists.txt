set(INCLUDE_DIRECTORY include)

FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG asio-1-36-0
)
FetchContent_MakeAvailable(asio)

add_library(asio INTERFACE)
add_library(mdnspp::asio ALIAS asio)

target_include_directories(asio INTERFACE
    $<BUILD_INTERFACE:${asio_SOURCE_DIR}/asio/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/${INCLUDE_DIRECTORY}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_link_libraries(asio INTERFACE core)
target_compile_definitions(asio INTERFACE MDNSPP_ENABLE_ASIO_POLICY)

install(FILES
    ${INCLUDE_DIRECTORY}/mdnspp/asio.h
    ${INCLUDE_DIRECTORY}/mdnspp/asio/asio_timer.h
    ${INCLUDE_DIRECTORY}/mdnspp/asio/asio_policy.h
    ${INCLUDE_DIRECTORY}/mdnspp/asio/asio_socket.h
    ${INCLUDE_DIRECTORY}/mdnspp/asio/async_query.h
    ${INCLUDE_DIRECTORY}/mdnspp/asio/async_start.h
    ${INCLUDE_DIRECTORY}/mdnspp/asio/async_observe.h
    ${INCLUDE_DIRECTORY}/mdnspp/asio/async_discover.h
    ${INCLUDE_DIRECTORY}/mdnspp/asio/asio_completion.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp/asio
)

install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/${INCLUDE_DIRECTORY}/mdnspp/asio.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp
)

install(DIRECTORY ${asio_SOURCE_DIR}/asio/include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(TARGETS asio EXPORT mdnsppTargets)
