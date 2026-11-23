if (NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    return()
endif ()

add_custom_target(netns_tests)

function(register_netns_test TEST_NAME)
    set_tests_properties(${TEST_NAME} PROPERTIES LABELS netns SKIP_RETURN_CODE 4)
    add_dependencies(netns_tests ${TEST_NAME})
endfunction()

make_subdir_test(netns_ipv6_selection_test netns/ipv6_selection.cpp)
register_netns_test(netns_ipv6_selection_test)

if (TARGET mdnspp::asio)
    make_asio_subdir_test(netns_ipv6_selection_asio_test netns/ipv6_selection_asio.cpp)
    register_netns_test(netns_ipv6_selection_asio_test)
endif ()
