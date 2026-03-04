if(MDNSPP_ENABLE_ASIO_POLICY)
    add_executable(observe observe.cpp)
    target_link_libraries(observe mdnspp_asio)
endif()
