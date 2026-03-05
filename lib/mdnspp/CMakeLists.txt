set(INCLUDE_DIRECTORY include)

set(PUBLIC_HEADERS
    ${INCLUDE_DIRECTORY}/mdnspp/dns.h
    ${INCLUDE_DIRECTORY}/mdnspp/parse.h
    ${INCLUDE_DIRECTORY}/mdnspp/policy.h
    ${INCLUDE_DIRECTORY}/mdnspp/basic_querier.h
    ${INCLUDE_DIRECTORY}/mdnspp/records.h
    ${INCLUDE_DIRECTORY}/mdnspp/endpoint.h
    ${INCLUDE_DIRECTORY}/mdnspp/basic_observer.h
    ${INCLUDE_DIRECTORY}/mdnspp/mdns_error.h
    ${INCLUDE_DIRECTORY}/mdnspp/service_info.h
    ${INCLUDE_DIRECTORY}/mdnspp/basic_service_server.h
    ${INCLUDE_DIRECTORY}/mdnspp/resolved_service.h
    ${INCLUDE_DIRECTORY}/mdnspp/basic_service_discovery.h
    ${INCLUDE_DIRECTORY}/mdnspp/defaults.h
)

add_library(mdnspp_core INTERFACE ${PUBLIC_HEADERS})

add_library(mdnspp::core ALIAS mdnspp_core)

target_include_directories(mdnspp_core
    INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/${INCLUDE_DIRECTORY}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

if(WIN32)
    target_link_libraries(mdnspp_core INTERFACE ws2_32)
endif()

install(TARGETS mdnspp_core
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

if(MDNSPP_ENABLE_DEFAULT_POLICY)
    add_library(mdnspp_native INTERFACE)
    add_library(mdnspp::native ALIAS mdnspp_native)
    target_include_directories(mdnspp_native INTERFACE
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/${INCLUDE_DIRECTORY}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
    )
    target_link_libraries(mdnspp_native INTERFACE mdnspp_core)

    install(FILES
        ${INCLUDE_DIRECTORY}/mdnspp/native.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/mdnspp
    )

    install(TARGETS mdnspp_native EXPORT mdnsppTargets)
endif()

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
