#ifndef HPP_GUARD_MDNSPP_ENCRYPT_SRC_BYTE_ORDER_H
#define HPP_GUARD_MDNSPP_ENCRYPT_SRC_BYTE_ORDER_H

#include <cstddef>
#include <cstdint>

namespace mdnspp::encrypt::detail {

inline void write_be16(std::byte *p, uint16_t v)
{
    p[0] = static_cast<std::byte>(static_cast<uint8_t>((v >> 8) & 0xFF));
    p[1] = static_cast<std::byte>(static_cast<uint8_t>(v & 0xFF));
}

inline void write_be32(std::byte *p, uint32_t v)
{
    p[0] = static_cast<std::byte>(static_cast<uint8_t>((v >> 24) & 0xFF));
    p[1] = static_cast<std::byte>(static_cast<uint8_t>((v >> 16) & 0xFF));
    p[2] = static_cast<std::byte>(static_cast<uint8_t>((v >> 8) & 0xFF));
    p[3] = static_cast<std::byte>(static_cast<uint8_t>(v & 0xFF));
}

inline void write_be64(std::byte *p, uint64_t v)
{
    p[0] = static_cast<std::byte>(static_cast<uint8_t>((v >> 56) & 0xFF));
    p[1] = static_cast<std::byte>(static_cast<uint8_t>((v >> 48) & 0xFF));
    p[2] = static_cast<std::byte>(static_cast<uint8_t>((v >> 40) & 0xFF));
    p[3] = static_cast<std::byte>(static_cast<uint8_t>((v >> 32) & 0xFF));
    p[4] = static_cast<std::byte>(static_cast<uint8_t>((v >> 24) & 0xFF));
    p[5] = static_cast<std::byte>(static_cast<uint8_t>((v >> 16) & 0xFF));
    p[6] = static_cast<std::byte>(static_cast<uint8_t>((v >> 8) & 0xFF));
    p[7] = static_cast<std::byte>(static_cast<uint8_t>(v & 0xFF));
}

inline uint16_t read_be16(const std::byte *p)
{
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(static_cast<uint8_t>(p[0])) << 8) |
        static_cast<uint16_t>(static_cast<uint8_t>(p[1])));
}

inline uint32_t read_be32(const std::byte *p)
{
    return (static_cast<uint32_t>(static_cast<uint8_t>(p[0])) << 24) |
           (static_cast<uint32_t>(static_cast<uint8_t>(p[1])) << 16) |
           (static_cast<uint32_t>(static_cast<uint8_t>(p[2])) << 8) |
            static_cast<uint32_t>(static_cast<uint8_t>(p[3]));
}

inline uint64_t read_be64(const std::byte *p)
{
    return (static_cast<uint64_t>(static_cast<uint8_t>(p[0])) << 56) |
           (static_cast<uint64_t>(static_cast<uint8_t>(p[1])) << 48) |
           (static_cast<uint64_t>(static_cast<uint8_t>(p[2])) << 40) |
           (static_cast<uint64_t>(static_cast<uint8_t>(p[3])) << 32) |
           (static_cast<uint64_t>(static_cast<uint8_t>(p[4])) << 24) |
           (static_cast<uint64_t>(static_cast<uint8_t>(p[5])) << 16) |
           (static_cast<uint64_t>(static_cast<uint8_t>(p[6])) << 8) |
            static_cast<uint64_t>(static_cast<uint8_t>(p[7]));
}

}

#endif
