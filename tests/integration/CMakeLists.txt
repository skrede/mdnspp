cmake_minimum_required(VERSION 3.25)
project(mdnspp_integration_test)

# Deliberately no CMAKE_CXX_STANDARD here: the consumer must inherit
# cxx_std_20 from the INTERFACE_COMPILE_FEATURES of the exported targets.

find_package(mdnspp CONFIG REQUIRED COMPONENTS inproc testing)

add_executable(integration_test main.cpp)
target_link_libraries(integration_test PRIVATE
    mdnspp::mdnspp
    mdnspp::inproc
    mdnspp::testing
)

if(TARGET mdnspp::asio)
    target_link_libraries(integration_test PRIVATE mdnspp::asio)
    target_compile_definitions(integration_test PRIVATE MDNSPP_HAS_ASIO=1)
endif()

if(TARGET mdnspp::encrypt)
    target_link_libraries(integration_test PRIVATE mdnspp::encrypt)
    target_compile_definitions(integration_test PRIVATE MDNSPP_HAS_ENCRYPT=1)
endif()
