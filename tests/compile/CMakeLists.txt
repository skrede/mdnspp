add_executable(defaults_compile_test ${CMAKE_CURRENT_LIST_DIR}/defaults_compile_test.cpp)
target_link_libraries(defaults_compile_test PRIVATE mdnspp)
target_compile_options(defaults_compile_test PRIVATE ${MDNSPP_WARNING_FLAGS})
add_test(NAME defaults_compile_test COMMAND defaults_compile_test)

if (MDNSPP_ENABLE_ENCRYPT)
    add_executable(encrypt_defaults_compile_test ${CMAKE_CURRENT_LIST_DIR}/encrypt_defaults_compile_test.cpp)
    target_link_libraries(encrypt_defaults_compile_test PRIVATE mdnspp::encrypt)
    target_compile_options(encrypt_defaults_compile_test PRIVATE ${MDNSPP_WARNING_FLAGS})
    add_test(NAME encrypt_defaults_compile_test COMMAND encrypt_defaults_compile_test)
endif ()

include("${CMAKE_CURRENT_LIST_DIR}/header_self_contained.cmake")
