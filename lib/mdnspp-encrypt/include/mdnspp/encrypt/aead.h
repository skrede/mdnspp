#ifndef HPP_GUARD_MDNSPP_ENCRYPT_AEAD_H
#define HPP_GUARD_MDNSPP_ENCRYPT_AEAD_H

#include "mdnspp/encrypt/encrypt_error.h"
#include "mdnspp/encrypt/packet_header.h"

#include <span>
#include <cstddef>
#include <cstdint>
#include <system_error>

namespace mdnspp::encrypt {

// Encrypt plaintext with XChaCha20-Poly1305 into out as header + ciphertext + 16-byte tag.
// out must hold at least plaintext.size() + encrypted_overhead bytes, otherwise
// encrypt_error::buffer_too_small is returned and nothing is written. The header fields
// serve as AAD; a random 24-byte nonce is generated per call and stored in the header.
// std::errc::not_supported is returned if libsodium cannot be initialized. written is set to
// the packet length on success and to 0 on every failure. out must not partially overlap plaintext.
std::error_code aead_encrypt(
    std::span<const std::byte, 32> key,
    const encrypted_packet_header &hdr,
    std::span<const std::byte> plaintext,
    std::span<std::byte> out,
    std::size_t &written);

// Decrypt a full wire packet (header + ciphertext + tag) into out.
// Checks run in order: libsodium initialization (std::errc::not_supported), size
// (invalid_header), magic (invalid_header), version (unsupported_version), out capacity of
// packet.size() - encrypted_overhead bytes (buffer_too_small), then the tag over the
// ciphertext with the header as AAD (decrypt_failed). written is set to the plaintext length
// on success and to 0 on every failure; out holds no usable data after a failure. out must not
// partially overlap packet.
std::error_code aead_decrypt(
    std::span<const std::byte, 32> key,
    std::span<const std::byte> packet,
    std::span<std::byte> out,
    std::size_t &written);

// Initialize the crypto subsystem. Must be called before any encrypt/decrypt.
// Thread-safe; safe to call multiple times. Returns true on success.
bool init_crypto();

// Nonzero 64-bit session identifier drawn from the libsodium CSPRNG; a socket draws one at
// construction so that every boot of a sender is a distinct replay-tracking session.
uint64_t random_session_id() noexcept;

// Overwrite memory with zeros. Compiler-barrier prevents dead-store elimination.
// Equivalent to sodium_memzero but without exposing the libsodium header to callers.
void secure_zero(void *buf, std::size_t len) noexcept;

}

#endif
