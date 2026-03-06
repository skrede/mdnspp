# DefaultPolicy examples (always built when MDNSPP_BUILD_EXAMPLES=ON)
add_executable(mdnspp_example_observe observe.cpp)
target_link_libraries(mdnspp_example_observe mdnspp::core)

add_executable(mdnspp_example_query query.cpp)
target_link_libraries(mdnspp_example_query mdnspp::core)

add_executable(mdnspp_example_discover discover.cpp)
target_link_libraries(mdnspp_example_discover mdnspp::core)

add_executable(mdnspp_example_serve serve.cpp)
target_link_libraries(mdnspp_example_serve mdnspp::core)

add_executable(mdnspp_example_multi_serve multi_serve.cpp)
target_link_libraries(mdnspp_example_multi_serve mdnspp::core)

# ASIO examples (additionally gated on MDNSPP_ENABLE_ASIO_POLICY)
if(MDNSPP_ENABLE_ASIO_POLICY)
    add_subdirectory(asio)
endif()
