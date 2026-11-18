set(MDNSPP_ASIO_HEADERS_INSTALLED OFF)
set(MDNSPP_ENCRYPT_EXPORTED OFF)
set(MDNSPP_ENCRYPT_SODIUM_PROVIDER "")

add_subdirectory(mdnspp)

if(MDNSPP_ENABLE_ASIO_POLICY)
    add_subdirectory(mdnspp-asio)
    add_dependencies(mdnspp_asio mdnspp)
endif()

add_subdirectory(mdnspp-testing)
add_dependencies(mdnspp_testing mdnspp)

add_subdirectory(mdnspp-inproc)
add_dependencies(mdnspp_inproc mdnspp)

if(MDNSPP_ENABLE_ENCRYPT)
    add_subdirectory(mdnspp-encrypt)
    add_dependencies(mdnspp_encrypt mdnspp)
endif()

# --- CMake package config ---
set(mdnspp_INSTALL_CMAKEDIR ${CMAKE_INSTALL_LIBDIR}/cmake/mdnspp)

install(EXPORT mdnsppTargets
    FILE mdnsppTargets.cmake
    NAMESPACE mdnspp::
    DESTINATION ${mdnspp_INSTALL_CMAKEDIR}
)

configure_package_config_file(
    ${PROJECT_SOURCE_DIR}/cmake/mdnsppConfig.cmake.in
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
