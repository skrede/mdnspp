#ifndef HPP_GUARD_MDNSPP_ENCRYPT_AEAD_HELPERS_H
#define HPP_GUARD_MDNSPP_ENCRYPT_AEAD_HELPERS_H

#include "mdnspp/encrypt/aead.h"
#include "mdnspp/encrypt/encrypt_error.h"
#include "mdnspp/encrypt/secure_key.h"
#include "mdnspp/encrypt/packet_header.h"
#include "mdnspp/encrypt/encrypt_options.h"

#include <array>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <algorithm>

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

#endif
