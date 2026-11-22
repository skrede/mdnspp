set(MDNSPP_SELF_CONTAINED_DIR "${CMAKE_CURRENT_BINARY_DIR}/self_contained")

function(mdnspp_write_unit OUT_VAR NAME CONTENT)
    set(unit "${MDNSPP_SELF_CONTAINED_DIR}/${NAME}.cpp")
    file(CONFIGURE OUTPUT "${unit}" CONTENT "${CONTENT}" @ONLY)
    set(${OUT_VAR} "${unit}" PARENT_SCOPE)
endfunction()

function(mdnspp_add_unit_check NAME LIBRARY)
    add_library(${NAME} OBJECT ${ARGN})
    target_link_libraries(${NAME} PRIVATE ${LIBRARY})
    target_compile_options(${NAME} PRIVATE ${MDNSPP_WARNING_FLAGS})
endfunction()

function(mdnspp_check_headers LIBRARY)
    if (NOT TARGET ${LIBRARY})
        return()
    endif ()
    get_target_property(source_dir ${LIBRARY} SOURCE_DIR)
    file(GLOB_RECURSE headers CONFIGURE_DEPENDS RELATIVE "${source_dir}/include" "${source_dir}/include/*.h")
    string(MAKE_C_IDENTIFIER "${LIBRARY}" library_id)
    set(units "")
    foreach (header IN LISTS headers)
        string(MAKE_C_IDENTIFIER "${header}" header_id)
        mdnspp_write_unit(unit "${library_id}/${header_id}" "#include \"${header}\"\n")
        list(APPEND units "${unit}")
    endforeach ()
    mdnspp_add_unit_check(${library_id}_self_contained ${LIBRARY} ${units})
endfunction()

# An explicit instantiation compiles every member of a class template, which a bare include does not.
function(mdnspp_inproc_template_unit OUT_VAR TEMPLATE)
    set(type "mdnspp::inproc::${TEMPLATE}")
    string(CONCAT content
        "#include \"mdnspp/inproc/${TEMPLATE}.h\"\n\n"
        "#include \"mdnspp/testing/test_clock.h\"\n\n"
        "#include <chrono>\n\n"
        "template class ${type}<std::chrono::steady_clock>;\n"
        "template class ${type}<mdnspp::testing::test_clock>;\n")
    mdnspp_write_unit(unit "inproc_templates/${TEMPLATE}" "${content}")
    set(${OUT_VAR} "${unit}" PARENT_SCOPE)
endfunction()

foreach (library IN ITEMS mdnspp mdnspp::testing mdnspp::inproc mdnspp::asio mdnspp::encrypt)
    mdnspp_check_headers(${library})
endforeach ()

set(inproc_template_units "")
foreach (template IN ITEMS inproc_executor inproc_timer inproc_bus inproc_socket)
    mdnspp_inproc_template_unit(unit ${template})
    list(APPEND inproc_template_units "${unit}")
endforeach ()
mdnspp_add_unit_check(inproc_template_instantiation mdnspp::inproc ${inproc_template_units})
