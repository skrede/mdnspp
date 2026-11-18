#include "aead_helpers.h"

#include "mdnspp/policy.h"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <system_error>

namespace {

using namespace mdnspp::encrypt;

constexpr std::byte filler{0xEE};

std::size_t max_plaintext()
{
    return mdnspp::detail::max_udp_payload - encrypted_overhead;
}

std::vector<std::byte> payload_of(std::size_t size)
{
    std::vector<std::byte> bytes(size);
    for(std::size_t i = 0; i < size; ++i)
        bytes[i] = static_cast<std::byte>((i * 7 + 1) & 0xFF);
    return bytes;
}

std::vector<std::byte> filled(std::size_t size, std::ptrdiff_t slack)
{
    return std::vector<std::byte>(static_cast<std::size_t>(static_cast<std::ptrdiff_t>(size) + slack), filler);
}

bool untouched(const std::vector<std::byte> &out, std::size_t from = 0)
{
    return std::all_of(out.begin() + static_cast<std::ptrdiff_t>(from), out.end(),
                       [](std::byte b) { return b == filler; });
}

void check_refused_as_too_small(const std::error_code &ec, std::size_t written, const std::vector<std::byte> &out)
{
    CHECK(ec == encrypt_error::buffer_too_small);
    CHECK(written == 0);
    CHECK(untouched(out));
}

enum class tamper { header_byte, ciphertext_byte, tag_byte, wrong_key };

}

TEST_CASE("aead_encrypt honors the output buffer boundary", "[aead][buffers]")
{
    const uint8_t flags = GENERATE(uint8_t{flag_encrypted}, uint8_t{0});
    const std::size_t size = GENERATE(values<std::size_t>({0, 1, 16, max_plaintext()}));
    const std::ptrdiff_t slack = GENERATE(std::ptrdiff_t{-1}, std::ptrdiff_t{0}, std::ptrdiff_t{1});

    const auto key = make_raw_key();
    const auto payload = payload_of(size);
    auto out = filled(size + encrypted_overhead, slack);
    std::size_t written = 99;
    const auto ec = aead_encrypt(key, make_header(1, 1, 0, flags), payload, out, written);

    if(slack < 0)
        return check_refused_as_too_small(ec, written, out);
    REQUIRE_FALSE(ec);
    CHECK(written == size + encrypted_overhead);
    const auto opened = unseal_packet(key, std::span<const std::byte>(out.data(), written));
    CHECK(opened.plaintext == payload);
}

TEST_CASE("aead_decrypt honors the output buffer boundary", "[aead][buffers]")
{
    const uint8_t flags = GENERATE(uint8_t{flag_encrypted}, uint8_t{0});
    const std::size_t size = GENERATE(values<std::size_t>({0, 1, 16, max_plaintext()}));
    const std::ptrdiff_t slack = GENERATE(std::ptrdiff_t{-1}, std::ptrdiff_t{0}, std::ptrdiff_t{1});
    if(size == 0 && slack < 0)
    {
        SUCCEED("no buffer holds fewer than zero bytes");
        return;
    }

    const auto key = make_raw_key();
    const auto payload = payload_of(size);
    const auto packet = seal_packet(key, make_header(1, 1, 0, flags), payload);
    auto out = filled(size, slack);
    std::size_t written = 99;
    const auto ec = aead_decrypt(key, packet, out, written);

    if(slack < 0)
        return check_refused_as_too_small(ec, written, out);
    REQUIRE_FALSE(ec);
    CHECK(written == size);
    CHECK(std::equal(payload.begin(), payload.end(), out.begin()));
    CHECK(untouched(out, size));
}

TEST_CASE("aead_decrypt rejects every tamper and reports nothing written", "[aead][buffers][tamper]")
{
    const uint8_t flags = GENERATE(uint8_t{flag_encrypted}, uint8_t{0});
    const auto kind = GENERATE(tamper::header_byte, tamper::ciphertext_byte, tamper::tag_byte, tamper::wrong_key);

    auto packet = seal_packet(make_raw_key(), make_header(1, 1, 0, flags), make_payload());
    if(kind == tamper::header_byte)
        packet[4] ^= std::byte{0x01};
    if(kind == tamper::ciphertext_byte)
        packet[encrypted_header_size] ^= std::byte{0xFF};
    if(kind == tamper::tag_byte)
        packet.back() ^= std::byte{0x01};

    const auto result = unseal_packet(make_raw_key(kind == tamper::wrong_key ? 0x43 : 0x42), packet);
    CHECK(result.ec == encrypt_error::decrypt_failed);
    CHECK(result.written == 0);
}

TEST_CASE("a packet shorter than header plus tag is rejected before any size arithmetic", "[aead][buffers]")
{
    const uint8_t flags = GENERATE(uint8_t{flag_encrypted}, uint8_t{0});
    const std::size_t size = GENERATE(values<std::size_t>({0, 1, encrypted_header_size, encrypted_overhead - 1}));

    const auto full = seal_packet(make_raw_key(), make_header(1, 1, 0, flags), make_payload());
    const auto result = unseal_packet(make_raw_key(), std::span<const std::byte>(full.data(), size));

    CHECK(result.ec == encrypt_error::invalid_header);
    CHECK(result.written == 0);
}
