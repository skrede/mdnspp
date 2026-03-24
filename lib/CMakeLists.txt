add_subdirectory(mdnspp)

add_subdirectory(mdnspp-asio)
if(TARGET mdnspp::asio)
    add_dependencies(mdnspp_asio mdnspp)
endif()

add_subdirectory(mdnspp-inproc)
add_dependencies(mdnspp_inproc mdnspp)

if(MDNSPP_BUILD_TESTS)
    add_subdirectory(mdnspp-testing)
    add_dependencies(mdnspp_testing mdnspp)
endif()

if(MDNSPP_ENABLE_ENCRYPT)
    add_subdirectory(mdnspp-encrypt)
    add_dependencies(mdnspp_encrypt mdnspp)
endif()
