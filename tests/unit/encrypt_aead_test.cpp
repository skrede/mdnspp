#include "mdnspp/encrypt/aead.h"
#include "mdnspp/encrypt/encrypt_error.h"
#include "mdnspp/encrypt/encrypt_options.h"
#include "mdnspp/encrypt/packet_header.h"
#include "mdnspp/encrypt/secure_key.h"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace {

// Build a 32-byte key filled with a repeating value.
std::array<std::byte, 32> make_raw_key(uint8_t fill = 0x42)
{
    std::array<std::byte, 32> k{};
    std::fill(k.begin(), k.end(), std::byte{fill});
    return k;
}

// Build a header with a non-zero sender_id and flag_encrypted set.
mdnspp::encrypt::encrypted_packet_header make_header(uint32_t sender = 1,
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

// A small DNS-like payload for use in roundtrip tests.
std::vector<std::byte> make_payload()
{
    // 12-byte "DNS header" with known content
    std::array<uint8_t, 12> raw{0x00, 0x01, 0x01, 0x00, 0x00, 0x01,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    std::vector<std::byte> v(raw.size());
    for(std::size_t i = 0; i < raw.size(); ++i)
        v[i] = static_cast<std::byte>(raw[i]);
    return v;
}

}

// ---------------------------------------------------------------------------
// Roundtrip
// ---------------------------------------------------------------------------

TEST_CASE("aead roundtrip returns original plaintext", "[aead][roundtrip]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header();
    auto payload = make_payload();

    auto packet = mdnspp::encrypt::aead_encrypt(key, hdr, payload);
    auto result = mdnspp::encrypt::aead_decrypt(key, packet);

    REQUIRE(result.has_value());
    REQUIRE(*result == payload);
}

TEST_CASE("aead roundtrip with empty plaintext", "[aead][roundtrip]")
{
    auto key = make_raw_key();
    auto hdr = make_header();

    std::vector<std::byte> empty;
    auto packet = mdnspp::encrypt::aead_encrypt(key, hdr, empty);
    auto result = mdnspp::encrypt::aead_decrypt(key, packet);

    REQUIRE(result.has_value());
    REQUIRE(result->empty());
}

// ---------------------------------------------------------------------------
// Output size
// ---------------------------------------------------------------------------

TEST_CASE("aead output size is header + plaintext + tag", "[aead][size]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header();
    auto payload = make_payload();

    auto packet = mdnspp::encrypt::aead_encrypt(key, hdr, payload);

    const std::size_t expected_size =
        mdnspp::encrypt::encrypted_header_size + payload.size() + mdnspp::encrypt::encrypted_tag_size;
    REQUIRE(packet.size() == expected_size);
}

TEST_CASE("aead output size for empty plaintext is exactly encrypted_overhead", "[aead][size]")
{
    auto key = make_raw_key();
    auto hdr = make_header();
    std::vector<std::byte> empty;

    auto packet = mdnspp::encrypt::aead_encrypt(key, hdr, empty);
    REQUIRE(packet.size() == mdnspp::encrypt::encrypted_overhead);
}

// ---------------------------------------------------------------------------
// Nonce uniqueness
// ---------------------------------------------------------------------------

TEST_CASE("aead two encrypts with same key+plaintext produce different ciphertexts", "[aead][nonce]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header();
    auto payload = make_payload();

    auto packet1 = mdnspp::encrypt::aead_encrypt(key, hdr, payload);
    auto packet2 = mdnspp::encrypt::aead_encrypt(key, hdr, payload);

    // Full packets must differ (nonce occupies bytes 20-43 of header, and ciphertext will differ)
    REQUIRE(packet1 != packet2);
}

// ---------------------------------------------------------------------------
// Tamper detection
// ---------------------------------------------------------------------------

TEST_CASE("flipping a byte in the auth tag causes decrypt_failed", "[aead][tamper]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header();
    auto payload = make_payload();

    auto packet = mdnspp::encrypt::aead_encrypt(key, hdr, payload);

    // The auth tag occupies the last 16 bytes
    packet.back() ^= std::byte{0x01};

    auto result = mdnspp::encrypt::aead_decrypt(key, packet);
    REQUIRE_FALSE(result.has_value());
    REQUIRE(result.error() == mdnspp::encrypt::encrypt_error::decrypt_failed);
}

TEST_CASE("flipping a byte in the ciphertext region causes decrypt_failed", "[aead][tamper]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header();
    auto payload = make_payload();

    auto packet = mdnspp::encrypt::aead_encrypt(key, hdr, payload);

    // Flip a byte in the ciphertext (immediately after the header)
    packet[mdnspp::encrypt::encrypted_header_size] ^= std::byte{0xFF};

    auto result = mdnspp::encrypt::aead_decrypt(key, packet);
    REQUIRE_FALSE(result.has_value());
    REQUIRE(result.error() == mdnspp::encrypt::encrypt_error::decrypt_failed);
}

TEST_CASE("flipping sender_id byte causes decrypt_failed", "[aead][tamper][header]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header();
    auto payload = make_payload();

    auto packet = mdnspp::encrypt::aead_encrypt(key, hdr, payload);

    // sender_id starts at offset 4 in the wire format (magic=2, version=1, flags=1)
    packet[4] ^= std::byte{0x01};

    auto result = mdnspp::encrypt::aead_decrypt(key, packet);
    REQUIRE_FALSE(result.has_value());
    REQUIRE(result.error() == mdnspp::encrypt::encrypt_error::decrypt_failed);
}

TEST_CASE("flipping sequence byte causes decrypt_failed", "[aead][tamper][header]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header();
    auto payload = make_payload();

    auto packet = mdnspp::encrypt::aead_encrypt(key, hdr, payload);

    // sequence starts at offset 8 (magic=2, version=1, flags=1, sender_id=4)
    packet[8] ^= std::byte{0x01};

    auto result = mdnspp::encrypt::aead_decrypt(key, packet);
    REQUIRE_FALSE(result.has_value());
    REQUIRE(result.error() == mdnspp::encrypt::encrypt_error::decrypt_failed);
}

TEST_CASE("flipping epoch byte causes decrypt_failed", "[aead][tamper][header]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header();
    auto payload = make_payload();

    auto packet = mdnspp::encrypt::aead_encrypt(key, hdr, payload);

    // epoch starts at offset 16 (magic=2, version=1, flags=1, sender_id=4, sequence=8)
    packet[16] ^= std::byte{0x01};

    auto result = mdnspp::encrypt::aead_decrypt(key, packet);
    REQUIRE_FALSE(result.has_value());
    REQUIRE(result.error() == mdnspp::encrypt::encrypt_error::decrypt_failed);
}

// ---------------------------------------------------------------------------
// Header validation
// ---------------------------------------------------------------------------

TEST_CASE("wrong magic returns invalid_header", "[aead][header]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header();
    auto payload = make_payload();

    auto packet = mdnspp::encrypt::aead_encrypt(key, hdr, payload);

    // Overwrite magic at offset 0-1
    packet[0] = std::byte{0xDE};
    packet[1] = std::byte{0xAD};

    auto result = mdnspp::encrypt::aead_decrypt(key, packet);
    REQUIRE_FALSE(result.has_value());
    REQUIRE(result.error() == mdnspp::encrypt::encrypt_error::invalid_header);
}

TEST_CASE("wrong version returns unsupported_version", "[aead][header]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header();
    auto payload = make_payload();

    auto packet = mdnspp::encrypt::aead_encrypt(key, hdr, payload);

    // Version at offset 2
    packet[2] = std::byte{0x02};

    auto result = mdnspp::encrypt::aead_decrypt(key, packet);
    REQUIRE_FALSE(result.has_value());
    REQUIRE(result.error() == mdnspp::encrypt::encrypt_error::unsupported_version);
}

TEST_CASE("too-short packet returns invalid_header", "[aead][header]")
{
    auto key = make_raw_key();

    // Construct a packet shorter than encrypted_overhead (60 bytes)
    std::vector<std::byte> short_packet(mdnspp::encrypt::encrypted_overhead - 1, std::byte{0});

    auto result = mdnspp::encrypt::aead_decrypt(key, short_packet);
    REQUIRE_FALSE(result.has_value());
    REQUIRE(result.error() == mdnspp::encrypt::encrypt_error::invalid_header);
}

// ---------------------------------------------------------------------------
// secure_key move zeroing (CRPT-01 / D-01)
// ---------------------------------------------------------------------------

TEST_CASE("secure_key move constructor zeroes source bytes", "[secure_key][move]")
{
    auto raw = make_raw_key(0x42);
    mdnspp::encrypt::secure_key src{raw};

    // Verify src has the expected bytes before move
    for(auto b : src.bytes())
        REQUIRE(b == std::byte{0x42});

    mdnspp::encrypt::secure_key dst{std::move(src)};

    // After move, source must be all-zero (sodium_memzero was called)
    for(auto b : src.bytes())  // NOLINT(bugprone-use-after-move) — intentional verification
        REQUIRE(b == std::byte{0});

    // Destination must carry the original key material
    for(auto b : dst.bytes())
        REQUIRE(b == std::byte{0x42});
}

TEST_CASE("secure_key move-assign zeroes source and previous destination bytes", "[secure_key][move]")
{
    auto raw_a = make_raw_key(0x42);
    auto raw_b = make_raw_key(0xBB);

    mdnspp::encrypt::secure_key a{raw_a};
    mdnspp::encrypt::secure_key b{raw_b};

    b = std::move(a);

    // a must be zeroed after move-assign
    for(auto byte : a.bytes())  // NOLINT(bugprone-use-after-move)
        REQUIRE(byte == std::byte{0});

    // b must now carry a's original material
    for(auto byte : b.bytes())
        REQUIRE(byte == std::byte{0x42});
}

// ---------------------------------------------------------------------------
// encrypt_options::validate() with non-zero sender_id (D-04)
// ---------------------------------------------------------------------------

TEST_CASE("encrypt_options validate succeeds with non-zero sender_id", "[encrypt_options][validate]")
{
    auto raw = make_raw_key();
    mdnspp::encrypt::encrypt_options opts;
    opts.psk       = mdnspp::encrypt::secure_key{raw};
    opts.sender_id = 1;

    // Must not assert/abort
    REQUIRE_NOTHROW(opts.validate());
}

// ---------------------------------------------------------------------------
// Auth-only mode (CRPT-06): flag_encrypted = 0
// ---------------------------------------------------------------------------

TEST_CASE("auth-only mode preserves cleartext payload in output", "[aead][auth-only]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header(1, 1, 0, 0);  // flags = 0 (auth-only)
    auto payload = make_payload();

    auto packet = mdnspp::encrypt::aead_encrypt(key, hdr, payload);

    // Total size: header + payload (cleartext) + tag
    REQUIRE(packet.size() == mdnspp::encrypt::encrypted_header_size + payload.size() + mdnspp::encrypt::encrypted_tag_size);

    // The payload region must match the original plaintext (cleartext, not encrypted)
    std::span<const std::byte> payload_region(
        packet.data() + mdnspp::encrypt::encrypted_header_size,
        payload.size());
    REQUIRE(std::equal(payload_region.begin(), payload_region.end(), payload.begin()));
}

TEST_CASE("auth-only mode roundtrip returns original plaintext", "[aead][auth-only]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header(1, 1, 0, 0);  // flags = 0 (auth-only)
    auto payload = make_payload();

    auto packet = mdnspp::encrypt::aead_encrypt(key, hdr, payload);
    auto result = mdnspp::encrypt::aead_decrypt(key, packet);

    REQUIRE(result.has_value());
    REQUIRE(*result == payload);
}

TEST_CASE("auth-only mode tag tamper is detected", "[aead][auth-only][tamper]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header(1, 1, 0, 0);  // flags = 0 (auth-only)
    auto payload = make_payload();

    auto packet = mdnspp::encrypt::aead_encrypt(key, hdr, payload);

    // Flip the last byte of the auth tag
    packet.back() ^= std::byte{0x01};

    auto result = mdnspp::encrypt::aead_decrypt(key, packet);
    REQUIRE_FALSE(result.has_value());
    REQUIRE(result.error() == mdnspp::encrypt::encrypt_error::decrypt_failed);
}
