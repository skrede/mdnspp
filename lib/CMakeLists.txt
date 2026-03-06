add_subdirectory(mdnspp)

if(MDNSPP_ENABLE_ASIO_POLICY)
    add_subdirectory(mdnspp-asio)
    add_dependencies(asio core)
endif()

if(MDNSPP_BUILD_TESTS)
    add_subdirectory(mdnspp-testing)
    add_dependencies(testing core)
endif()
