#ifndef HPP_GUARD_MDNSPP_CORPUS_SEEDS_H
#define HPP_GUARD_MDNSPP_CORPUS_SEEDS_H

#include <vector>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <filesystem>
#include <string_view>
#include <initializer_list>

namespace mdnspp::corpus {

inline std::vector<std::byte> bytes(std::initializer_list<uint8_t> vals)
{
    std::vector<std::byte> out;
    out.reserve(vals.size());
    for(uint8_t v : vals)
        out.push_back(static_cast<std::byte>(v));
    return out;
}

inline std::vector<std::byte> text(std::string_view s)
{
    std::vector<std::byte> out;
    out.reserve(s.size());
    for(char c : s)
        out.push_back(static_cast<std::byte>(c));
    return out;
}

inline void write_seed(const std::filesystem::path &dir, std::string_view name, std::vector<std::byte> data)
{
    std::filesystem::create_directories(dir);
    std::ofstream f(dir / name, std::ios::binary);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    f.write(reinterpret_cast<const char *>(data.data()), static_cast<std::streamsize>(data.size()));
}

// Appends a dotted name ("_fuzz._tcp.local.") in DNS wire label format.
inline void append_name(std::vector<std::byte> &v, std::string_view name)
{
    std::size_t pos = 0;
    while(pos < name.size())
    {
        std::size_t dot = name.find('.', pos);
        if(dot == std::string_view::npos)
            dot = name.size();
        v.push_back(static_cast<std::byte>(dot - pos));
        for(std::size_t i = pos; i < dot; ++i)
            v.push_back(static_cast<std::byte>(name[i]));
        pos = dot + 1;
    }
    v.push_back(std::byte{0x00}); // root label
}

inline void append_u16(std::vector<std::byte> &v, uint16_t value)
{
    v.push_back(static_cast<std::byte>(value >> 8 & 0xFF));
    v.push_back(static_cast<std::byte>(value & 0xFF));
}

void gen_read_dns_name(const std::filesystem::path &root);
void gen_encode_dns_name(const std::filesystem::path &root);
void gen_dns_name(const std::filesystem::path &root);
void gen_parse_a(const std::filesystem::path &root);
void gen_parse_aaaa(const std::filesystem::path &root);
void gen_parse_ptr(const std::filesystem::path &root);
void gen_parse_srv(const std::filesystem::path &root);
void gen_parse_txt(const std::filesystem::path &root);
void gen_walk_frame(const std::filesystem::path &root);
void gen_server_query(const std::filesystem::path &root);
void gen_roundtrip(const std::filesystem::path &root);

}

#endif
