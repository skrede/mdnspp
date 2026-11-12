#include "aead_helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <vector>
#include <cstddef>
#include <algorithm>

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

TEST_CASE("auth-only mode preserves cleartext payload in output", "[aead][auth-only]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header(1, 1, 0, 0);
    auto payload = make_payload();

    auto packet = mdnspp::encrypt::aead_encrypt(key, hdr, payload);

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

    auto packet = mdnspp::encrypt::aead_encrypt(key, hdr, payload);
    auto result = mdnspp::encrypt::aead_decrypt(key, packet);

    REQUIRE(result.has_value());
    REQUIRE(*result == payload);
}
