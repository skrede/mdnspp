add_executable(01_local_bus 01_local_bus.cpp)
target_link_libraries(01_local_bus PRIVATE mdnspp::local)
