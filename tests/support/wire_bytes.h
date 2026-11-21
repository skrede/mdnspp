#ifndef HPP_GUARD_MDNSPP_SUPPORT_WIRE_BYTES_H
#define HPP_GUARD_MDNSPP_SUPPORT_WIRE_BYTES_H

#include <vector>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <initializer_list>

namespace mdnspp::test_support {

inline std::vector<std::byte> bytes(std::initializer_list<uint8_t> vals)
{
    std::vector<std::byte> v;
    v.reserve(vals.size());
    for(auto b : vals)
        v.push_back(static_cast<std::byte>(b));
    return v;
}

inline void push_u16_be(std::vector<std::byte> &buf, uint16_t v)
{
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>(v >> 8)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>(v & 0xFF)));
}

inline void push_u32_be(std::vector<std::byte> &buf, uint32_t v)
{
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>((v >> 24) & 0xFF)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>((v >> 16) & 0xFF)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>((v >> 8) & 0xFF)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>(v & 0xFF)));
}

inline uint16_t read_u16_be(const auto &buf, std::size_t offset)
{
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(static_cast<uint8_t>(buf[offset])) << 8) |
        static_cast<uint16_t>(static_cast<uint8_t>(buf[offset + 1])));
}

inline std::vector<std::byte> encode_name(std::string_view name)
{
    std::vector<std::byte> result;
    if(!name.empty() && name.back() == '.')
        name.remove_suffix(1);

    std::size_t pos = 0;
    while(pos < name.size())
    {
        std::size_t dot = name.find('.', pos);
        if(dot == std::string_view::npos)
            dot = name.size();
        std::size_t len = dot - pos;
        result.push_back(static_cast<std::byte>(static_cast<uint8_t>(len)));
        for(std::size_t i = pos; i < dot; ++i)
            result.push_back(static_cast<std::byte>(static_cast<uint8_t>(name[i])));
        pos = (dot < name.size()) ? dot + 1 : name.size();
    }
    result.push_back(static_cast<std::byte>(0x00));
    return result;
}

}

#endif
