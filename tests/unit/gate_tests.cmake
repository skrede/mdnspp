make_subdir_test(gate_header_rules_test gate/header_rules.cpp)
make_subdir_test(gate_peer_header_test gate/peer_header.cpp)

make_subdir_test(gate_peer_port_test gate/peer_port.cpp)
target_link_libraries(gate_peer_port_test PRIVATE mdnspp::inproc)
if (MDNSPP_ENABLE_ENCRYPT)
    target_link_libraries(gate_peer_port_test PRIVATE mdnspp::encrypt)
    target_compile_definitions(gate_peer_port_test PRIVATE MDNSPP_ENABLE_ENCRYPT=1)
endif ()
