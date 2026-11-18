make_subdir_test(compat_odr_test compat/odr_tu20.cpp)

add_library(compat_odr_cxx23 OBJECT "${CMAKE_CURRENT_LIST_DIR}/compat/odr_tu23.cpp")
target_include_directories(compat_odr_cxx23 PRIVATE "${CMAKE_CURRENT_LIST_DIR}")
target_link_libraries(compat_odr_cxx23 PRIVATE mdnspp)
target_compile_options(compat_odr_cxx23 PRIVATE ${MDNSPP_WARNING_FLAGS})
set_target_properties(compat_odr_cxx23 PROPERTIES CXX_STANDARD 23 CXX_STANDARD_REQUIRED ON)
target_link_libraries(compat_odr_test PRIVATE compat_odr_cxx23)

make_subdir_test(expected_surface_test compat/expected_surface.cpp)
make_subdir_test(expected_surface_test_cxx23 compat/expected_surface.cpp)
set_target_properties(expected_surface_test_cxx23 PROPERTIES CXX_STANDARD 23 CXX_STANDARD_REQUIRED ON)

make_subdir_test(move_only_function_test compat/move_only_function.cpp)
target_sources(move_only_function_test PRIVATE "${CMAKE_CURRENT_LIST_DIR}/compat/move_only_function_surface.cpp")
if (NOT CMAKE_CXX_FLAGS MATCHES "fsanitize=thread")
    target_sources(move_only_function_test PRIVATE
        "${CMAKE_CURRENT_LIST_DIR}/compat/move_only_function_storage.cpp"
        "${CMAKE_CURRENT_LIST_DIR}/../support/alloc_counter.cpp")
endif ()
