if(MDNSPP_ENABLE_ASIO_POLICY)
    add_executable(mdnspp_asio_01_observer 01_observer.cpp)
    target_link_libraries(mdnspp_asio_01_observer PRIVATE mdnspp::mdnspp mdnspp::asio)

    add_executable(mdnspp_asio_02_querier 02_querier.cpp)
    target_link_libraries(mdnspp_asio_02_querier PRIVATE mdnspp::mdnspp mdnspp::asio)

    add_executable(mdnspp_asio_03_discover 03_discover.cpp)
    target_link_libraries(mdnspp_asio_03_discover PRIVATE mdnspp::mdnspp mdnspp::asio)

    add_executable(mdnspp_asio_04_monitor 04_monitor.cpp)
    target_link_libraries(mdnspp_asio_04_monitor PRIVATE mdnspp::mdnspp mdnspp::asio)

    add_executable(mdnspp_asio_05_server 05_server.cpp)
    target_link_libraries(mdnspp_asio_05_server PRIVATE mdnspp::mdnspp mdnspp::asio)

    add_executable(mdnspp_asio_06_coroutine 06_coroutine.cpp)
    target_link_libraries(mdnspp_asio_06_coroutine PRIVATE mdnspp::mdnspp mdnspp::asio)

    add_executable(mdnspp_asio_07_use_future 07_use_future.cpp)
    target_link_libraries(mdnspp_asio_07_use_future PRIVATE mdnspp::mdnspp mdnspp::asio)
endif()
