set(INCLUDE_DIRECTORY include)

add_library(testing INTERFACE)
add_library(mdnspp::testing ALIAS testing)

target_include_directories(testing INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/${INCLUDE_DIRECTORY}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_link_libraries(testing INTERFACE core)

install(FILES
    ${INCLUDE_DIRECTORY}/mdnspp/testing/mock_policy.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp/testing
)

install(TARGETS testing EXPORT mdnsppTargets)
