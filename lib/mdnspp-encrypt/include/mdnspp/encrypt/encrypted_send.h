#ifndef HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_SEND_H
#define HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_SEND_H

#include "mdnspp/encrypt/aead.h"
#include "mdnspp/encrypt/key_ring.h"
#include "mdnspp/encrypt/packet_header.h"

#include <span>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <system_error>

namespace mdnspp::encrypt {

// The key copy taken for sending is zeroed when it goes out of scope.
inline std::error_code seal_outgoing(key_ring &keys, std::atomic<uint64_t> &sequence,
                                     const encrypted_packet_header &header_template,
                                     std::span<const std::byte> plaintext, std::span<std::byte> out,
                                     std::size_t &written)
{
    auto hdr = header_template;
    hdr.sequence = sequence.fetch_add(1, std::memory_order_relaxed) + 1;
    const auto sending = keys.key_for_send();
    hdr.epoch = sending.epoch;
    return aead_encrypt(sending.key.span(), hdr, plaintext, out, written);
}

}

#endif
