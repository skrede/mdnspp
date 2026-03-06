# AsioPolicy examples (built when MDNSPP_ENABLE_ASIO_POLICY=ON)
add_executable(mdnspp_example_asio_observe observe.cpp)
target_link_libraries(mdnspp_example_asio_observe mdnspp::mdnspp mdnspp::asio)

add_executable(mdnspp_example_asio_query query.cpp)
target_link_libraries(mdnspp_example_asio_query mdnspp::mdnspp mdnspp::asio)

add_executable(mdnspp_example_asio_discover discover.cpp)
target_link_libraries(mdnspp_example_asio_discover mdnspp::mdnspp mdnspp::asio)

add_executable(mdnspp_example_asio_serve serve.cpp)
target_link_libraries(mdnspp_example_asio_serve mdnspp::mdnspp mdnspp::asio)
