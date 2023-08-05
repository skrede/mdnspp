set(UNIT_TEST_RESOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/resources")
set(UNIT_TEST_INCLUDE ${CMAKE_CURRENT_LIST_DIR}/include)
set(MDNSPP_SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/../src/)

function(make_test TEST_FILE)
    add_executable(${TEST_FILE} "${TEST_FILE}.cpp")
    target_link_libraries(${TEST_FILE} PRIVATE mdnspp Catch2::Catch2WithMain)
    target_include_directories(${TEST_FILE} PRIVATE ${MDNSPP_SOURCE_DIR} ${UNIT_TEST_INCLUDE})
    add_test(NAME ${TEST_FILE} COMMAND ${TEST_FILE})
endfunction()

make_test(log_test)

