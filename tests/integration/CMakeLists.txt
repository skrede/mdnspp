cmake_minimum_required(VERSION 3.25)
project(mdnspp_integration_test)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(mdnspp CONFIG REQUIRED)

add_executable(integration_test main.cpp)
target_link_libraries(integration_test PRIVATE mdnspp::mdnspp_core)
