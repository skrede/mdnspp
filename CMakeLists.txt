cmake_minimum_required(VERSION 3.25)
project(mDNSpp)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(Boost_NO_WARN_NEW_VERSIONS ON)

set(SOURCE_DIRECTORY src)
set(INCLUDE_DIRECTORY include)

option(BUILD_EXAMPLES off)

if(${CMAKE_TOOLCHAIN_FILE})
    find_path(MDNS_INCLUDE_DIRS "mdns.h")
else()
    set(MDNS_INCLUDE_DIRS ${INCLUDE_DIRECTORY}/mdns)
endif()

set(PUBLIC_HEADERS
    ${INCLUDE_DIRECTORY}/mdnspp/query.h
    ${INCLUDE_DIRECTORY}/mdnspp/service.h
    ${INCLUDE_DIRECTORY}/mdnspp/observer.h
    ${INCLUDE_DIRECTORY}/mdnspp/exception.h
    ${INCLUDE_DIRECTORY}/mdnspp/discovery.h
)

set(CORE_SOURCES
    ${SOURCE_DIRECTORY}/mdnspp/query.cpp
    ${SOURCE_DIRECTORY}/mdnspp/service.cpp
    ${SOURCE_DIRECTORY}/mdnspp/observer.cpp
    ${SOURCE_DIRECTORY}/mdnspp/discovery.cpp
    ${SOURCE_DIRECTORY}/mdnspp/mdns_util.h
    ${SOURCE_DIRECTORY}/mdnspp/mdns_util.cpp

    ${SOURCE_DIRECTORY}/mdnspp/impl/mdnsbase.h
    ${SOURCE_DIRECTORY}/mdnspp/impl/mdnsbase.cpp
    ${SOURCE_DIRECTORY}/mdnspp/impl/queryprivate.h
    ${SOURCE_DIRECTORY}/mdnspp/impl/queryprivate.cpp
    ${SOURCE_DIRECTORY}/mdnspp/impl/serviceprivate.h
    ${SOURCE_DIRECTORY}/mdnspp/impl/serviceprivate.cpp
    ${SOURCE_DIRECTORY}/mdnspp/impl/observerprivate.h
    ${SOURCE_DIRECTORY}/mdnspp/impl/observerprivate.cpp
    ${SOURCE_DIRECTORY}/mdnspp/impl/discoveryprivate.h
    ${SOURCE_DIRECTORY}/mdnspp/impl/discoveryprivate.cpp
)

add_library(mdnspp SHARED
    ${PUBLIC_HEADERS}
    ${CORE_SOURCES}
)

add_library(mdnspp::mdnspp ALIAS mdnspp)

target_include_directories(mdnspp
    PUBLIC ${INCLUDE_DIRECTORY} ${MDNS_INCLUDE_DIRS}
    PRIVATE ${SOURCE_DIRECTORY}
)

if(${BUILD_EXAMPLES})
    add_subdirectory(example)
endif()