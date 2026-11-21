#ifndef HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_SEND_H
#define HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_SEND_H

#include "mdnspp/encrypt/aead.h"
#include "mdnspp/encrypt/key_ring.h"
#include "mdnspp/encrypt/packet_header.h"

#include <span>
#include <cstddef>
#include <cstdint>
#include <system_error>

namespace mdnspp::encrypt {

inline std::error_code seal_outgoing(key_ring &keys, uint64_t &sequence,
                                     const encrypted_packet_header &header_template,
                                     std::span<const std::byte> plaintext, std::span<std::byte> out,
                                     std::size_t &written)
{
    written = 0;
    const auto sending = keys.key_for_send();
    if(!sending)
        return std::make_error_code(std::errc::operation_not_permitted);
    auto hdr = header_template;
    hdr.sequence = ++sequence;
    hdr.epoch = sending->epoch;
    return aead_encrypt(sending->key.span(), hdr, plaintext, out, written);
}

}

#endif
