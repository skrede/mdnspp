add_executable(mdnspp_example_observer_01_basic 01_basic.cpp)
target_link_libraries(mdnspp_example_observer_01_basic mdnspp::mdnspp)

if(MDNSPP_ENABLE_ASIO_POLICY)
    add_executable(mdnspp_example_observer_02_asio_callback 02_asio_callback.cpp)
    target_link_libraries(mdnspp_example_observer_02_asio_callback mdnspp::mdnspp mdnspp::asio)
endif()
