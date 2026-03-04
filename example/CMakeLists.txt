if(MDNSPP_ENABLE_ASIO_POLICY)
    add_executable(observe observe.cpp)
    target_link_libraries(observe mdnspp_asio)

    add_executable(discover discover.cpp)
    target_link_libraries(discover mdnspp_asio)

    add_executable(query query.cpp)
    target_link_libraries(query mdnspp_asio)

    add_executable(serve serve.cpp)
    target_link_libraries(serve mdnspp_asio)
endif()
