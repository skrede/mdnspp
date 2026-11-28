#ifndef HPP_GUARD_MDNSPP_ENCRYPT_AEAD_HELPERS_H
#define HPP_GUARD_MDNSPP_ENCRYPT_AEAD_HELPERS_H

#include "mdnspp/encrypt/aead.h"
#include "mdnspp/encrypt/secure_key.h"
#include "mdnspp/encrypt/encrypt_error.h"
#include "mdnspp/encrypt/packet_header.h"
#include "mdnspp/encrypt/encrypt_options.h"

#include <span>
#include <array>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <system_error>

inline std::array<std::byte, 32> make_raw_key(uint8_t fill = 0x42)
{
    std::array<std::byte, 32> k{};
    std::fill(k.begin(), k.end(), std::byte{fill});
    return k;
}

inline mdnspp::encrypt::encrypted_packet_header make_header(uint32_t sender = 1,
                                                            uint64_t seq    = 1,
                                                            uint32_t epoch  = 0,
                                                            uint8_t  flags  = mdnspp::encrypt::flag_encrypted)
{
    mdnspp::encrypt::encrypted_packet_header h;
    h.sender_id = sender;
    h.sequence  = seq;
    h.epoch     = epoch;
    h.flags     = flags;
    return h;
}

inline std::vector<std::byte> make_payload()
{
    std::array<uint8_t, 12> raw{0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::vector<std::byte> v(raw.size());
    for(std::size_t i = 0; i < raw.size(); ++i)
        v[i] = static_cast<std::byte>(raw[i]);
    return v;
}

struct unsealed
{
    std::error_code ec;
    std::vector<std::byte> plaintext;
    std::size_t written;
};

inline std::vector<std::byte> seal_packet(std::span<const std::byte, 32> key,
                                          const mdnspp::encrypt::encrypted_packet_header &hdr,
                                          std::span<const std::byte> plaintext)
{
    std::vector<std::byte> out(mdnspp::encrypt::encrypted_overhead + plaintext.size());
    std::size_t written = 0;
    mdnspp::encrypt::aead_encrypt(key, hdr, plaintext, out, written);
    out.resize(written);
    return out;
}

inline unsealed unseal_packet(std::span<const std::byte, 32> key, std::span<const std::byte> packet)
{
    unsealed result{{}, std::vector<std::byte>(packet.size()), 0};
    result.ec = mdnspp::encrypt::aead_decrypt(key, packet, result.plaintext, result.written);
    result.plaintext.resize(result.written);
    return result;
}

#endif
