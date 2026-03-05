if(MDNSPP_ENABLE_ASIO_POLICY)
    add_executable(observe observe.cpp)
    target_link_libraries(observe mdnspp::core mdnspp::asio)

    add_executable(discover discover.cpp)
    target_link_libraries(discover mdnspp::core mdnspp::asio)

    add_executable(query query.cpp)
    target_link_libraries(query mdnspp::core mdnspp::asio)

    add_executable(serve serve.cpp)
    target_link_libraries(serve mdnspp::core mdnspp::asio)
endif()
