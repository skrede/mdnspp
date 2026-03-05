# DefaultPolicy examples (always built when MDNSPP_BUILD_EXAMPLES=ON)
add_executable(mdnspp_example_observe observe.cpp)
target_link_libraries(mdnspp_example_observe mdnspp::native)

add_executable(mdnspp_example_query query.cpp)
target_link_libraries(mdnspp_example_query mdnspp::native)

add_executable(mdnspp_example_discover discover.cpp)
target_link_libraries(mdnspp_example_discover mdnspp::native)

add_executable(mdnspp_example_serve serve.cpp)
target_link_libraries(mdnspp_example_serve mdnspp::native)

add_executable(mdnspp_example_multi_serve multi_serve.cpp)
target_link_libraries(mdnspp_example_multi_serve mdnspp::native)

# ASIO examples (additionally gated on MDNSPP_ENABLE_ASIO_POLICY)
if(MDNSPP_ENABLE_ASIO_POLICY)
    add_subdirectory(asio)
endif()
