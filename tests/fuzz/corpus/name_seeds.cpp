#include "seeds.h"

#include <string>
#include <vector>
#include <cstddef>
#include <utility>
#include <filesystem>

namespace mdnspp::corpus {

namespace {

void read_name_labels(const std::filesystem::path &dir)
{
    write_seed(dir, "simple", bytes({0x05, 'h', 'e', 'l', 'l', 'o', 0x00}));
    write_seed(dir, "two_labels", bytes({0x05, 'h', 'e', 'l', 'l', 'o', 0x05, 'w', 'o', 'r', 'l', 'd', 0x00}));
    write_seed(dir, "empty", {});
    write_seed(dir, "root_only", bytes({0x00}));
}

void read_name_pointers(const std::filesystem::path &dir)
{
    // "a.b." followed by a pointer back to offset 0
    write_seed(dir, "compression_ptr", bytes({0x01, 'a', 0x01, 'b', 0x00, 0xC0, 0x00}));
    write_seed(dir, "self_ptr", bytes({0xC0, 0x00}));
    write_seed(dir, "forward_ptr", bytes({0xC0, 0x10}));
    // Every pointer jumps two bytes back, so reading from offset 10 takes five hops, one more than max_hops = 4.
    write_seed(dir, "deep_chain",
        bytes({0x00, 0x00,          // offset 0: root label + pad
               0xC0, 0x00,          // offset 2: ptr -> 0 (hop 1)
               0xC0, 0x02,          // offset 4: ptr -> 2 (hop 2)
               0xC0, 0x04,          // offset 6: ptr -> 4 (hop 3)
               0xC0, 0x06,          // offset 8: ptr -> 6 (hop 4)
               0xC0, 0x08}));       // offset 10: ptr -> 8 (hop 5)
    write_seed(dir, "truncated_ptr", bytes({0xC0}));
}

void read_name_limits(const std::filesystem::path &dir)
{
    // label length 64, one past the RFC 1035 maximum of 63
    std::vector<std::byte> label{std::byte{0x40}};
    label.insert(label.end(), 64, static_cast<std::byte>('x'));
    label.push_back(std::byte{0x00});
    write_seed(dir, "label_64", std::move(label));

    // 32 labels of 8 bytes: 288 wire bytes, past the 255-byte name limit
    std::vector<std::byte> name;
    for(std::size_t i = 0; i < 32; ++i)
    {
        name.push_back(std::byte{8});
        name.insert(name.end(), 8, static_cast<std::byte>('a'));
    }
    name.push_back(std::byte{0x00});
    write_seed(dir, "name_256", std::move(name));
}

}

void gen_read_dns_name(const std::filesystem::path &root)
{
    const std::filesystem::path dir = root / "read_dns_name";
    read_name_labels(dir);
    read_name_pointers(dir);
    read_name_limits(dir);
}

void gen_encode_dns_name(const std::filesystem::path &root)
{
    const std::filesystem::path dir = root / "encode_dns_name";
    write_seed(dir, "simple", text("hello.local."));
    write_seed(dir, "empty", {});
    write_seed(dir, "no_trailing_dot", text("a.b"));
    // a 64-character label, one past the 63-byte limit
    write_seed(dir, "long_label", text(std::string(64, 'a') + ".local."));

    // 50 labels of 4 characters trimmed to a 254-character name at the boundary
    std::string max_length;
    for(std::size_t i = 0; i < 50; ++i)
        max_length += "aaaa.";
    max_length.resize(254);
    write_seed(dir, "max_length", text(max_length));
    write_seed(dir, "dots_only", text("..."));
}

void gen_dns_name(const std::filesystem::path &root)
{
    const std::filesystem::path dir = root / "dns_name";
    write_seed(dir, "service_type", text("_http._tcp.local."));
    write_seed(dir, "uppercase", text("HELLO.LOCAL."));
    write_seed(dir, "empty", {});
    write_seed(dir, "no_trailing_dot", text("a.b"));

    // 1000 characters in a repeating pattern, so the seed stays deterministic
    std::vector<std::byte> huge;
    huge.reserve(1000);
    for(std::size_t i = 0; i < 1000; ++i)
        huge.push_back(static_cast<std::byte>('a' + i % 26));
    write_seed(dir, "huge", std::move(huge));
}

}
