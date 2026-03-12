set(INCLUDE_DIRECTORY include)

add_library(mdnspp_testing INTERFACE)
add_library(mdnspp::testing ALIAS mdnspp_testing)

target_include_directories(mdnspp_testing INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/${INCLUDE_DIRECTORY}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_link_libraries(mdnspp_testing INTERFACE mdnspp)

install(FILES
    ${INCLUDE_DIRECTORY}/mdnspp/testing/mock_policy.h
    ${INCLUDE_DIRECTORY}/mdnspp/testing/test_clock.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp/testing
)

install(TARGETS mdnspp_testing EXPORT mdnsppTargets)
