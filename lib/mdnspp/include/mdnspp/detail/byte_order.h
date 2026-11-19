#ifndef HPP_GUARD_MDNSPP_DETAIL_BYTE_ORDER_H
#define HPP_GUARD_MDNSPP_DETAIL_BYTE_ORDER_H

#include <vector>
#include <cstddef>
#include <cstdint>

namespace mdnspp::detail {

constexpr uint16_t read_u16_be(const std::byte *p)
{
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(static_cast<uint8_t>(p[0])) << 8) |
        static_cast<uint16_t>(static_cast<uint8_t>(p[1]))
    );
}

constexpr uint32_t read_u32_be(const std::byte *p)
{
    return (static_cast<uint32_t>(static_cast<uint8_t>(p[0])) << 24) |
        (static_cast<uint32_t>(static_cast<uint8_t>(p[1])) << 16) |
        (static_cast<uint32_t>(static_cast<uint8_t>(p[2])) << 8) |
        static_cast<uint32_t>(static_cast<uint8_t>(p[3]));
}

constexpr uint64_t read_u64_be(const std::byte *p)
{
    return (static_cast<uint64_t>(read_u32_be(p)) << 32) | read_u32_be(p + 4);
}

constexpr void write_u16_be(std::byte *p, uint16_t v)
{
    p[0] = static_cast<std::byte>(static_cast<uint8_t>(v >> 8));
    p[1] = static_cast<std::byte>(static_cast<uint8_t>(v & 0xFF));
}

constexpr void write_u32_be(std::byte *p, uint32_t v)
{
    write_u16_be(p, static_cast<uint16_t>(v >> 16));
    write_u16_be(p + 2, static_cast<uint16_t>(v & 0xFFFF));
}

constexpr void write_u64_be(std::byte *p, uint64_t v)
{
    write_u32_be(p, static_cast<uint32_t>(v >> 32));
    write_u32_be(p + 4, static_cast<uint32_t>(v & 0xFFFFFFFF));
}

constexpr void push_u16_be(std::vector<std::byte> &buf, uint16_t v)
{
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>(v >> 8)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>(v & 0xFF)));
}

constexpr void push_u32_be(std::vector<std::byte> &buf, uint32_t v)
{
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>((v >> 24) & 0xFF)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>((v >> 16) & 0xFF)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>((v >> 8) & 0xFF)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>(v & 0xFF)));
}

}

#endif
