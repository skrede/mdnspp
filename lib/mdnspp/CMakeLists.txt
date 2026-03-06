set(INCLUDE_DIRECTORY include)

set(PUBLIC_HEADERS
    ${INCLUDE_DIRECTORY}/mdnspp/dns.h
    ${INCLUDE_DIRECTORY}/mdnspp/parse.h
    ${INCLUDE_DIRECTORY}/mdnspp/policy.h
    ${INCLUDE_DIRECTORY}/mdnspp/defaults.h
    ${INCLUDE_DIRECTORY}/mdnspp/records.h
    ${INCLUDE_DIRECTORY}/mdnspp/endpoint.h
    ${INCLUDE_DIRECTORY}/mdnspp/mdns_error.h
    ${INCLUDE_DIRECTORY}/mdnspp/service_info.h
    ${INCLUDE_DIRECTORY}/mdnspp/basic_querier.h
    ${INCLUDE_DIRECTORY}/mdnspp/basic_observer.h
    ${INCLUDE_DIRECTORY}/mdnspp/resolved_service.h
    ${INCLUDE_DIRECTORY}/mdnspp/resolved_service.h
    ${INCLUDE_DIRECTORY}/mdnspp/basic_service_server.h
    ${INCLUDE_DIRECTORY}/mdnspp/basic_service_discovery.h
)

add_library(core INTERFACE ${PUBLIC_HEADERS})

add_library(mdnspp::core ALIAS core)

target_include_directories(core
    INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/${INCLUDE_DIRECTORY}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

if(WIN32)
    target_link_libraries(core INTERFACE ws2_32)
endif()

install(TARGETS core
    EXPORT mdnsppTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(FILES ${PUBLIC_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp
)

install(DIRECTORY ${INCLUDE_DIRECTORY}/mdnspp/default/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp/default
)

install(DIRECTORY ${INCLUDE_DIRECTORY}/mdnspp/detail/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp/detail
)

# --- CMake package config ---
set(mdnspp_INSTALL_CMAKEDIR ${CMAKE_INSTALL_LIBDIR}/cmake/mdnspp)

install(EXPORT mdnsppTargets
    FILE mdnsppTargets.cmake
    NAMESPACE mdnspp::
    DESTINATION ${mdnspp_INSTALL_CMAKEDIR}
)

configure_package_config_file(
    ${CMAKE_SOURCE_DIR}/cmake/mdnsppConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/mdnsppConfig.cmake"
    INSTALL_DESTINATION ${mdnspp_INSTALL_CMAKEDIR}
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/mdnsppConfigVersion.cmake"
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/mdnsppConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/mdnsppConfigVersion.cmake"
    DESTINATION ${mdnspp_INSTALL_CMAKEDIR}
)
