#include "aead_helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <array>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <algorithm>

namespace {

mdnspp::encrypt::encrypted_packet_header layout_header()
{
    mdnspp::encrypt::encrypted_packet_header h;
    h.version    = 0x05;
    h.flags      = 0x06;
    h.sender_id  = 0x01020304;
    h.session_id = 0x1112131415161718;
    h.sequence   = 0x2122232425262728;
    h.epoch      = 0x31323334;
    for(std::size_t i = 0; i < h.nonce.size(); ++i)
        h.nonce[i] = static_cast<std::byte>(0x40 + i);
    return h;
}

std::array<std::byte, mdnspp::encrypt::encrypted_header_size> layout_bytes()
{
    constexpr std::array<uint8_t, 28> fixed{0x4D, 0x43, 0x05, 0x06, 0x01, 0x02, 0x03, 0x04, 0x11, 0x12,
                                            0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x21, 0x22, 0x23, 0x24,
                                            0x25, 0x26, 0x27, 0x28, 0x31, 0x32, 0x33, 0x34};
    std::array<std::byte, mdnspp::encrypt::encrypted_header_size> b{};
    for(std::size_t i = 0; i < b.size(); ++i)
        b[i] = static_cast<std::byte>(i < fixed.size() ? fixed[i] : 0x40 + (i - fixed.size()));
    return b;
}

}

TEST_CASE("aead roundtrip returns original plaintext", "[aead][roundtrip]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header();
    auto payload = make_payload();

    auto packet = seal_packet(key, hdr, payload);
    auto result = unseal_packet(key, packet);

    REQUIRE_FALSE(result.ec);
    REQUIRE(result.plaintext == payload);
}

TEST_CASE("aead roundtrip with empty plaintext", "[aead][roundtrip]")
{
    auto key = make_raw_key();
    auto hdr = make_header();

    std::vector<std::byte> empty;
    auto packet = seal_packet(key, hdr, empty);
    auto result = unseal_packet(key, packet);

    REQUIRE_FALSE(result.ec);
    REQUIRE(result.plaintext.empty());
}

TEST_CASE("aead output size is header + plaintext + tag", "[aead][size]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header();
    auto payload = make_payload();

    auto packet = seal_packet(key, hdr, payload);

    const std::size_t expected_size =
        mdnspp::encrypt::encrypted_header_size + payload.size() + mdnspp::encrypt::encrypted_tag_size;
    REQUIRE(packet.size() == expected_size);
}

TEST_CASE("aead output size for empty plaintext is exactly encrypted_overhead", "[aead][size]")
{
    auto key = make_raw_key();
    auto hdr = make_header();
    std::vector<std::byte> empty;

    auto packet = seal_packet(key, hdr, empty);
    REQUIRE(packet.size() == mdnspp::encrypt::encrypted_overhead);
}

TEST_CASE("aead two encrypts with same key+plaintext produce different ciphertexts", "[aead][nonce]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header();
    auto payload = make_payload();

    auto packet1 = seal_packet(key, hdr, payload);
    auto packet2 = seal_packet(key, hdr, payload);

    // The random nonce is part of the header, and the ciphertext differs with it
    REQUIRE(packet1 != packet2);
}

TEST_CASE("auth-only mode preserves cleartext payload in output", "[aead][auth-only]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header(1, 1, 0, 0);
    auto payload = make_payload();

    auto packet = seal_packet(key, hdr, payload);

    REQUIRE(packet.size() == mdnspp::encrypt::encrypted_header_size + payload.size() + mdnspp::encrypt::encrypted_tag_size);

    std::span<const std::byte> payload_region(
        packet.data() + mdnspp::encrypt::encrypted_header_size,
        payload.size());
    REQUIRE(std::equal(payload_region.begin(), payload_region.end(), payload.begin()));
}

TEST_CASE("auth-only mode roundtrip returns original plaintext", "[aead][auth-only]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header(1, 1, 0, 0);
    auto payload = make_payload();

    auto packet = seal_packet(key, hdr, payload);
    auto result = unseal_packet(key, packet);

    REQUIRE_FALSE(result.ec);
    REQUIRE(result.plaintext == payload);
}

TEST_CASE("serialized header fields sit at their big-endian offsets", "[header][layout]")
{
    const auto wire     = mdnspp::encrypt::serialize_header(layout_header());
    const auto expected = layout_bytes();

    for(std::size_t i = 0; i < wire.size(); ++i)
    {
        CAPTURE(i);
        REQUIRE(wire[i] == expected[i]);
    }
}

TEST_CASE("deserialized header fields match their big-endian bytes", "[header][layout]")
{
    const auto wire = layout_bytes();
    const auto hdr  = mdnspp::encrypt::deserialize_header(wire.data());
    const auto ref  = layout_header();

    REQUIRE(hdr.magic == mdnspp::encrypt::encrypted_magic);
    REQUIRE(hdr.version == ref.version);
    REQUIRE(hdr.flags == ref.flags);
    REQUIRE(hdr.sender_id == ref.sender_id);
    REQUIRE(hdr.session_id == ref.session_id);
    REQUIRE(hdr.sequence == ref.sequence);
    REQUIRE(hdr.epoch == ref.epoch);
    REQUIRE(hdr.nonce == ref.nonce);
}
