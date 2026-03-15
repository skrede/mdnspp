set(INCLUDE_DIRECTORY include)

add_library(mdnspp_inproc INTERFACE)
add_library(mdnspp::inproc ALIAS mdnspp_inproc)

target_include_directories(mdnspp_inproc INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/${INCLUDE_DIRECTORY}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_link_libraries(mdnspp_inproc INTERFACE mdnspp mdnspp::testing)

install(DIRECTORY ${INCLUDE_DIRECTORY}/mdnspp/inproc/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp/inproc
)

install(TARGETS mdnspp_inproc EXPORT mdnsppTargets)
