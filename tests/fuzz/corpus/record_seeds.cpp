#include "seeds.h"

#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <filesystem>

// The parse harnesses split their input into record metadata fields and a raw payload with FuzzedDataProvider,
// so these seeds are plausible mixes of metadata bytes and payload.
namespace mdnspp::corpus {

void gen_parse_a(const std::filesystem::path &root)
{
    const std::filesystem::path dir = root / "parse_a";
    write_seed(dir, "valid_4", bytes({192, 168, 1, 1}));
    write_seed(dir, "short_3", bytes({0x01, 0x02, 0x03}));
    write_seed(dir, "long_5", bytes({0x01, 0x02, 0x03, 0x04, 0x05}));
    write_seed(dir, "empty", {});
}

void gen_parse_aaaa(const std::filesystem::path &root)
{
    const std::filesystem::path dir = root / "parse_aaaa";
    write_seed(dir, "valid_16", bytes({0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1}));
    write_seed(dir, "short_15", bytes({0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0}));
    write_seed(dir, "long_17", bytes({0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1, 0}));
    write_seed(dir, "empty", {});
}

void gen_parse_ptr(const std::filesystem::path &root)
{
    const std::filesystem::path dir = root / "parse_ptr";
    write_seed(dir, "valid_ptr",
        bytes({0x05, '_', 'h', 't', 't', 'p',
               0x04, '_', 't', 'c', 'p',
               0x05, 'l', 'o', 'c', 'a', 'l',
               0x00}));
    // the label announces 5 bytes but only 4 follow
    write_seed(dir, "truncated_name", bytes({0x05, 'h', 'e', 'l', 'l'}));
    write_seed(dir, "empty", {});
}

void gen_parse_srv(const std::filesystem::path &root)
{
    const std::filesystem::path dir = root / "parse_srv";
    write_seed(dir, "valid_srv",
        bytes({0x00, 0x00,  // priority
               0x00, 0x00,  // weight
               0x00, 0x50,  // port = 80
               0x04, 'h', 'o', 's', 't',
               0x05, 'l', 'o', 'c', 'a', 'l',
               0x00}));
    // priority, weight and port without the target name
    write_seed(dir, "no_name", bytes({0x00, 0x01, 0x00, 0x00, 0x1F, 0x40}));
    write_seed(dir, "empty", {});
}

void gen_parse_txt(const std::filesystem::path &root)
{
    const std::filesystem::path dir = root / "parse_txt";
    write_seed(dir, "valid_txt", bytes({0x05, 'h', 'e', 'l', 'l', 'o', 0x05, 'w', 'o', 'r', 'l', 'd'}));

    // an entry length of 255 with 10 bytes remaining
    std::vector<std::byte> overrun{std::byte{0xFF}};
    for(uint8_t i = 0; i < 10; ++i)
        overrun.push_back(static_cast<std::byte>(i));
    write_seed(dir, "overrun", std::move(overrun));
    write_seed(dir, "empty", {});
}

}
