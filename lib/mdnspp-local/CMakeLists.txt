set(INCLUDE_DIRECTORY include)

add_library(mdnspp_local INTERFACE)
add_library(mdnspp::local ALIAS mdnspp_local)

target_include_directories(mdnspp_local INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/${INCLUDE_DIRECTORY}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_link_libraries(mdnspp_local INTERFACE mdnspp mdnspp::testing)

install(DIRECTORY ${INCLUDE_DIRECTORY}/mdnspp/local/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp/local
)

install(TARGETS mdnspp_local EXPORT mdnsppTargets)
