#include "aead_helpers.h"

#include <catch2/generators/catch_generators.hpp>
#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <cstddef>

TEST_CASE("flipping a byte in the auth tag causes decrypt_failed", "[aead][tamper]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header();
    auto payload = make_payload();

    auto packet = seal_packet(key, hdr, payload);

    // The auth tag occupies the last 16 bytes
    packet.back() ^= std::byte{0x01};

    auto result = unseal_packet(key, packet);
    REQUIRE(result.ec == mdnspp::encrypt::encrypt_error::decrypt_failed);
    REQUIRE(result.written == 0);
}

TEST_CASE("flipping a byte in the ciphertext region causes decrypt_failed", "[aead][tamper]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header();
    auto payload = make_payload();

    auto packet = seal_packet(key, hdr, payload);

    // Flip a byte in the ciphertext (immediately after the header)
    packet[mdnspp::encrypt::encrypted_header_size] ^= std::byte{0xFF};

    auto result = unseal_packet(key, packet);
    REQUIRE(result.ec == mdnspp::encrypt::encrypt_error::decrypt_failed);
    REQUIRE(result.written == 0);
}

TEST_CASE("flipping sender_id byte causes decrypt_failed", "[aead][tamper][header]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header();
    auto payload = make_payload();

    auto packet = seal_packet(key, hdr, payload);

    // sender_id starts at offset 4 in the wire format (magic=2, version=1, flags=1)
    packet[4] ^= std::byte{0x01};

    auto result = unseal_packet(key, packet);
    REQUIRE(result.ec == mdnspp::encrypt::encrypt_error::decrypt_failed);
    REQUIRE(result.written == 0);
}

TEST_CASE("flipping a session_id byte causes decrypt_failed", "[aead][tamper][header]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header();
    auto payload = make_payload();
    hdr.session_id = 0x0102030405060708;

    const auto offset = GENERATE(std::size_t{8}, std::size_t{11}, std::size_t{15});
    auto packet = seal_packet(key, hdr, payload);
    packet[offset] ^= std::byte{0x01};

    auto result = unseal_packet(key, packet);
    REQUIRE(result.ec == mdnspp::encrypt::encrypt_error::decrypt_failed);
    REQUIRE(result.written == 0);
}

TEST_CASE("flipping sequence byte causes decrypt_failed", "[aead][tamper][header]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header();
    auto payload = make_payload();

    auto packet = seal_packet(key, hdr, payload);

    // sequence starts at offset 16 (magic=2, version=1, flags=1, sender_id=4, session_id=8)
    packet[16] ^= std::byte{0x01};

    auto result = unseal_packet(key, packet);
    REQUIRE(result.ec == mdnspp::encrypt::encrypt_error::decrypt_failed);
    REQUIRE(result.written == 0);
}

TEST_CASE("flipping epoch byte causes decrypt_failed", "[aead][tamper][header]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header();
    auto payload = make_payload();

    auto packet = seal_packet(key, hdr, payload);

    // epoch starts at offset 24 (magic=2, version=1, flags=1, sender_id=4, session_id=8, sequence=8)
    packet[24] ^= std::byte{0x01};

    auto result = unseal_packet(key, packet);
    REQUIRE(result.ec == mdnspp::encrypt::encrypt_error::decrypt_failed);
    REQUIRE(result.written == 0);
}

TEST_CASE("wrong magic returns invalid_header", "[aead][header]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header();
    auto payload = make_payload();

    auto packet = seal_packet(key, hdr, payload);

    // Overwrite magic at offset 0-1
    packet[0] = std::byte{0xDE};
    packet[1] = std::byte{0xAD};

    auto result = unseal_packet(key, packet);
    REQUIRE(result.ec == mdnspp::encrypt::encrypt_error::invalid_header);
    REQUIRE(result.written == 0);
}

TEST_CASE("wrong version returns unsupported_version", "[aead][header]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header();
    auto payload = make_payload();

    auto packet = seal_packet(key, hdr, payload);

    // Version at offset 2
    packet[2] = std::byte{0x01};

    auto result = unseal_packet(key, packet);
    REQUIRE(result.ec == mdnspp::encrypt::encrypt_error::unsupported_version);
    REQUIRE(result.written == 0);
}

TEST_CASE("too-short packet returns invalid_header", "[aead][header]")
{
    auto key = make_raw_key();

    // Construct a packet shorter than encrypted_overhead
    std::vector<std::byte> short_packet(mdnspp::encrypt::encrypted_overhead - 1, std::byte{0});

    auto result = unseal_packet(key, short_packet);
    REQUIRE(result.ec == mdnspp::encrypt::encrypt_error::invalid_header);
    REQUIRE(result.written == 0);
}

TEST_CASE("auth-only mode tag tamper is detected", "[aead][auth-only][tamper]")
{
    auto key     = make_raw_key();
    auto hdr     = make_header(1, 1, 0, 0);
    auto payload = make_payload();

    auto packet = seal_packet(key, hdr, payload);

    // Flip the last byte of the auth tag
    packet.back() ^= std::byte{0x01};

    auto result = unseal_packet(key, packet);
    REQUIRE(result.ec == mdnspp::encrypt::encrypt_error::decrypt_failed);
    REQUIRE(result.written == 0);
}
