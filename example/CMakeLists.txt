# DefaultPolicy examples (always built when MDNSPP_BUILD_EXAMPLES=ON)
add_executable(mdnspp_example_observe observe.cpp)
target_link_libraries(mdnspp_example_observe mdnspp::mdnspp)

add_executable(mdnspp_example_query query.cpp)
target_link_libraries(mdnspp_example_query mdnspp::mdnspp)

add_executable(mdnspp_example_discover discover.cpp)
target_link_libraries(mdnspp_example_discover mdnspp::mdnspp)

add_executable(mdnspp_example_serve serve.cpp)
target_link_libraries(mdnspp_example_serve mdnspp::mdnspp)

add_executable(mdnspp_example_multi_serve multi_serve.cpp)
target_link_libraries(mdnspp_example_multi_serve mdnspp::mdnspp)

add_executable(mdnspp_example_conflict_resolution conflict_resolution.cpp)
target_link_libraries(mdnspp_example_conflict_resolution mdnspp::mdnspp)

add_executable(mdnspp_example_enumerate_types enumerate_types.cpp)
target_link_libraries(mdnspp_example_enumerate_types mdnspp::mdnspp)

add_executable(mdnspp_example_subtype_discovery subtype_discovery.cpp)
target_link_libraries(mdnspp_example_subtype_discovery mdnspp::mdnspp)

# ASIO examples (additionally gated on MDNSPP_ENABLE_ASIO_POLICY)
if(MDNSPP_ENABLE_ASIO_POLICY)
    add_subdirectory(asio)
endif()
