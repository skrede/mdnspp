#ifndef HPP_GUARD_MDNSPP_ENCRYPT_AEAD_H
#define HPP_GUARD_MDNSPP_ENCRYPT_AEAD_H

#include "mdnspp/encrypt/encrypt_error.h"
#include "mdnspp/encrypt/packet_header.h"

#include "mdnspp/detail/compat.h"

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>

namespace mdnspp::encrypt {

// Encrypt plaintext using XChaCha20-Poly1305.
// Returns: serialized header (44 bytes) + ciphertext + 16-byte auth tag.
// The header fields (sender_id, sequence, epoch) serve as AAD.
// A random 24-byte nonce is generated per call and stored in the header.
std::vector<std::byte> aead_encrypt(
    std::span<const std::byte, 32> key,
    const encrypted_packet_header &hdr,
    std::span<const std::byte> plaintext);

// Decrypt a full wire packet (header + ciphertext + tag).
// Returns decrypted plaintext on success, encrypt_error on failure.
// Verifies auth tag over ciphertext with header as AAD.
expected<std::vector<std::byte>, encrypt_error> aead_decrypt(
    std::span<const std::byte, 32> key,
    std::span<const std::byte> packet);

// Initialize the crypto subsystem. Must be called before any encrypt/decrypt.
// Thread-safe; safe to call multiple times. Returns true on success.
bool init_crypto();

// Per-boot randomized starting value for the packet sequence counter: the top
// 24 bits are drawn from the CSPRNG (libsodium randombytes_buf), the low 40
// bits are zero. A restarted sender therefore resumes at least 2^40 sequence
// numbers away from any position of its previous run unless both runs draw the
// same 24-bit value (probability 2^-24 per restart); in that residual case the
// sender's packets are classified as replays by receivers that retain the old
// run's window state until the counter passes the old maximum.
uint64_t random_sequence_start() noexcept;

// Overwrite memory with zeros. Compiler-barrier prevents dead-store elimination.
// Equivalent to sodium_memzero but without exposing the libsodium header to callers.
void secure_zero(void *buf, std::size_t len) noexcept;

}

#endif
