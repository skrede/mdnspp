add_executable(mdnspp_example_querier_01_basic 01_basic.cpp)
target_link_libraries(mdnspp_example_querier_01_basic PRIVATE mdnspp::mdnspp)

if(MDNSPP_ENABLE_ASIO_POLICY)
    add_executable(mdnspp_example_querier_02_asio_callback 02_asio_callback.cpp)
    target_link_libraries(mdnspp_example_querier_02_asio_callback PRIVATE mdnspp::mdnspp mdnspp::asio)
endif()
