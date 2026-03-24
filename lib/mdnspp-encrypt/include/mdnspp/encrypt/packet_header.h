#ifndef HPP_GUARD_MDNSPP_ENCRYPT_PACKET_HEADER_H
#define HPP_GUARD_MDNSPP_ENCRYPT_PACKET_HEADER_H

#include <array>
#include <cstddef>
#include <cstdint>

namespace mdnspp {

inline constexpr uint16_t encrypted_magic = 0x4D43;  // 'MC' big-endian
inline constexpr uint8_t encrypted_version = 0x01;
inline constexpr std::size_t encrypted_header_size = 44;
inline constexpr std::size_t encrypted_tag_size = 16;
inline constexpr std::size_t encrypted_nonce_size = 24;
inline constexpr std::size_t encrypted_overhead = encrypted_header_size + encrypted_tag_size;  // 60

// Flags bit definitions
inline constexpr uint8_t flag_encrypted = 0x01;   // bit 0: 1=encrypted, 0=auth-only

struct encrypted_packet_header
{
    uint16_t magic{encrypted_magic};
    uint8_t version{encrypted_version};
    uint8_t flags{flag_encrypted};
    uint32_t sender_id{0};
    uint64_t sequence{0};
    uint32_t epoch{0};
    std::array<std::byte, encrypted_nonce_size> nonce{};
};

// Serialize header to wire format (network byte order, 44 bytes).
// Returns exactly encrypted_header_size bytes.
std::array<std::byte, encrypted_header_size> serialize_header(const encrypted_packet_header &hdr);

// Deserialize from wire bytes. Returns header with fields in host byte order.
// Caller must ensure buf points to at least encrypted_header_size bytes.
encrypted_packet_header deserialize_header(const std::byte *buf);

}

#endif
