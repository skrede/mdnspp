add_executable(discover discover.cpp)
target_link_libraries(discover mdnspp)

add_executable(inquire inquire.cpp)
target_link_libraries(inquire mdnspp)

add_executable(serve serve.cpp)
target_link_libraries(serve mdnspp)

add_executable(observe observe.cpp)
target_link_libraries(observe mdnspp)

add_executable(log_sink log_sink.cpp)
target_link_libraries(log_sink mdnspp)