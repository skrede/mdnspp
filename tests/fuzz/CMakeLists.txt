function(make_fuzz_target TARGET_FILE)
    add_executable(${TARGET_FILE} "${TARGET_FILE}.cpp")
    target_link_libraries(${TARGET_FILE} PRIVATE mdnspp::mdnspp)
    target_compile_options(${TARGET_FILE} PRIVATE
        -fsanitize=fuzzer,address,undefined
        -fno-sanitize-recover=all
        -fno-omit-frame-pointer
        -g
        -O1
    )
    target_link_options(${TARGET_FILE} PRIVATE -fsanitize=fuzzer,address,undefined)
endfunction()

make_fuzz_target(fuzz_read_dns_name)
make_fuzz_target(fuzz_skip_dns_name)
make_fuzz_target(fuzz_encode_dns_name)
make_fuzz_target(fuzz_dns_name)
make_fuzz_target(fuzz_parse_a)
make_fuzz_target(fuzz_parse_aaaa)
make_fuzz_target(fuzz_parse_ptr)
make_fuzz_target(fuzz_parse_srv)
make_fuzz_target(fuzz_parse_txt)
make_fuzz_target(fuzz_walk_dns_frame_raw)
make_fuzz_target(fuzz_walk_dns_frame_smart)
make_fuzz_target(fuzz_roundtrip_name)
make_fuzz_target(fuzz_roundtrip_dns_name)

add_executable(generate_corpus generate_corpus.cpp)
target_link_libraries(generate_corpus PRIVATE mdnspp)
target_compile_options(generate_corpus PRIVATE ${MDNSPP_WARNING_FLAGS})

set(CORPUS_DIR "${CMAKE_BINARY_DIR}/fuzz_corpus")

add_custom_target(fuzz_corpus ALL
    COMMAND generate_corpus "${CORPUS_DIR}"
    DEPENDS generate_corpus
    COMMENT "Generating fuzz seed corpus"
)
