#include "seeds.h"

#include <filesystem>

int main(int argc, char *argv[])
{
    using namespace mdnspp::corpus;
    const std::filesystem::path root = (argc > 1) ? argv[1] : "fuzz_corpus";

    gen_read_dns_name(root);
    gen_encode_dns_name(root);
    gen_dns_name(root);
    gen_parse_a(root);
    gen_parse_aaaa(root);
    gen_parse_ptr(root);
    gen_parse_srv(root);
    gen_parse_txt(root);
    gen_walk_frame(root);
    gen_roundtrip(root);
    gen_server_query(root);

    return 0;
}
