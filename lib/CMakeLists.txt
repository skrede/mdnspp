add_subdirectory(mdnspp)

if(MDNSPP_ENABLE_ASIO_POLICY)
    add_subdirectory(mdnspp-asio)
    add_dependencies(mdnspp_asio mdnspp)
endif()

if(MDNSPP_BUILD_TESTS)
    add_subdirectory(mdnspp-testing)
    add_dependencies(mdnspp_testing mdnspp)
    add_subdirectory(mdnspp-local)
    add_dependencies(mdnspp_local mdnspp)
endif()
