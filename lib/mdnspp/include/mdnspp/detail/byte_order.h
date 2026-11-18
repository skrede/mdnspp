#ifndef HPP_GUARD_MDNSPP_DETAIL_BYTE_ORDER_H
#define HPP_GUARD_MDNSPP_DETAIL_BYTE_ORDER_H

#include <vector>
#include <cstddef>
#include <cstdint>

namespace mdnspp::detail {

// Reads a big-endian uint16 from two consecutive bytes.
// Uses shift-and-or — no reinterpret_cast, well-defined for std::byte.
constexpr uint16_t read_u16_be(const std::byte *p)
{
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(static_cast<uint8_t>(p[0])) << 8) |
        static_cast<uint16_t>(static_cast<uint8_t>(p[1]))
    );
}

// Reads a big-endian uint32 from four consecutive bytes.
constexpr uint32_t read_u32_be(const std::byte *p)
{
    return (static_cast<uint32_t>(static_cast<uint8_t>(p[0])) << 24) |
        (static_cast<uint32_t>(static_cast<uint8_t>(p[1])) << 16) |
        (static_cast<uint32_t>(static_cast<uint8_t>(p[2])) << 8) |
        static_cast<uint32_t>(static_cast<uint8_t>(p[3]));
}

// Appends a 16-bit value to buf in big-endian byte order (most-significant byte first).
constexpr void push_u16_be(std::vector<std::byte> &buf, uint16_t v)
{
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>(v >> 8)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>(v & 0xFF)));
}

// Appends a 32-bit value to buf in big-endian byte order.
constexpr void push_u32_be(std::vector<std::byte> &buf, uint32_t v)
{
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>((v >> 24) & 0xFF)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>((v >> 16) & 0xFF)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>((v >> 8) & 0xFF)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>(v & 0xFF)));
}

}

#endif
