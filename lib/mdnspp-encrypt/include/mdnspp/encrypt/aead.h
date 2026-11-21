#ifndef HPP_GUARD_MDNSPP_ENCRYPT_AEAD_H
#define HPP_GUARD_MDNSPP_ENCRYPT_AEAD_H

#include "mdnspp/encrypt/encrypt_error.h"
#include "mdnspp/encrypt/packet_header.h"

#include <span>
#include <cstddef>
#include <cstdint>
#include <system_error>

namespace mdnspp::encrypt {

std::error_code aead_encrypt(
    std::span<const std::byte, 32> key,
    const encrypted_packet_header &hdr,
    std::span<const std::byte> plaintext,
    std::span<std::byte> out,
    std::size_t &written);

std::error_code aead_decrypt(
    std::span<const std::byte, 32> key,
    std::span<const std::byte> packet,
    std::span<std::byte> out,
    std::size_t &written);

bool init_crypto();

// A keyed socket draws one at construction, so every boot of a sender is a distinct replay-tracking session.
uint64_t random_session_id() noexcept;

// sodium_memzero, which the compiler cannot elide as a dead store, without exposing the libsodium header.
void secure_zero(void *buf, std::size_t len) noexcept;

}

#endif
