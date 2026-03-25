#include "mdnspp/encrypt/aead.h"
#include "mdnspp/encrypt/packet_header.h"

#include <catch2/catch_test_macros.hpp>
#include <catch2/benchmark/catch_benchmark.hpp>

#include <span>
#include <array>
#include <vector>
#include <cstddef>
#include <cstring>
#include <algorithm>

namespace {

std::array<std::byte, 32> make_key()
{
    std::array<std::byte, 32> k{};
    k.fill(std::byte{0x42});
    return k;
}

std::vector<std::byte> make_payload(std::size_t size = 200)
{
    return std::vector<std::byte>(size, std::byte{0xAB});
}

}

TEST_CASE("Encrypt benchmark smoke test", "[encrypt]")
{
    REQUIRE(mdnspp::init_crypto());

    auto key = make_key();
    auto payload = make_payload(200);

    mdnspp::encrypted_packet_header hdr;
    hdr.sender_id = 1;
    hdr.sequence  = 1;
    auto encrypted = mdnspp::aead_encrypt(std::span<const std::byte, 32>(key), hdr, payload);

    REQUIRE(encrypted.size() > payload.size());

    auto decrypted = mdnspp::aead_decrypt(
        std::span<const std::byte, 32>(key),
        std::span<const std::byte>(encrypted));

    REQUIRE(decrypted.has_value());
    REQUIRE(decrypted->size() == payload.size());
    REQUIRE(std::ranges::equal(*decrypted, payload));
}

TEST_CASE("Cleartext baseline throughput", "[!benchmark][encrypt]")
{
    auto payload64   = make_payload(64);
    auto payload200  = make_payload(200);
    auto payload512  = make_payload(512);
    auto payload1400 = make_payload(1400);

    BENCHMARK("cleartext copy 64-byte payload")
    {
        std::vector<std::byte> dst(payload64.size());
        std::memcpy(dst.data(), payload64.data(), payload64.size());
        return dst;
    };

    BENCHMARK("cleartext copy 200-byte payload")
    {
        std::vector<std::byte> dst(payload200.size());
        std::memcpy(dst.data(), payload200.data(), payload200.size());
        return dst;
    };

    BENCHMARK("cleartext copy 512-byte payload")
    {
        std::vector<std::byte> dst(payload512.size());
        std::memcpy(dst.data(), payload512.data(), payload512.size());
        return dst;
    };

    BENCHMARK("cleartext copy 1400-byte payload")
    {
        std::vector<std::byte> dst(payload1400.size());
        std::memcpy(dst.data(), payload1400.data(), payload1400.size());
        return dst;
    };
}

TEST_CASE("Encrypt throughput", "[!benchmark][encrypt]")
{
    REQUIRE(mdnspp::init_crypto());

    auto key     = make_key();
    auto payload = make_payload();

    BENCHMARK("encrypt 200-byte payload")
    {
        mdnspp::encrypted_packet_header hdr;
        hdr.sender_id = 1;
        hdr.sequence  = 1;
        return mdnspp::aead_encrypt(std::span<const std::byte, 32>(key), hdr, payload);
    };
}

TEST_CASE("Decrypt throughput", "[!benchmark][encrypt]")
{
    REQUIRE(mdnspp::init_crypto());

    auto key     = make_key();
    auto payload = make_payload();

    mdnspp::encrypted_packet_header hdr;
    hdr.sender_id = 1;
    hdr.sequence  = 1;
    auto packet = mdnspp::aead_encrypt(std::span<const std::byte, 32>(key), hdr, payload);

    BENCHMARK("decrypt 200-byte payload")
    {
        return mdnspp::aead_decrypt(
            std::span<const std::byte, 32>(key),
            std::span<const std::byte>(packet));
    };
}

TEST_CASE("Encrypt varying payload sizes", "[!benchmark][encrypt]")
{
    REQUIRE(mdnspp::init_crypto());

    auto key        = make_key();
    auto payload64  = make_payload(64);
    auto payload512 = make_payload(512);
    auto payload1400 = make_payload(1400);

    BENCHMARK("encrypt 64-byte payload")
    {
        mdnspp::encrypted_packet_header hdr;
        hdr.sender_id = 1;
        hdr.sequence  = 1;
        return mdnspp::aead_encrypt(std::span<const std::byte, 32>(key), hdr, payload64);
    };

    BENCHMARK("encrypt 512-byte payload")
    {
        mdnspp::encrypted_packet_header hdr;
        hdr.sender_id = 1;
        hdr.sequence  = 1;
        return mdnspp::aead_encrypt(std::span<const std::byte, 32>(key), hdr, payload512);
    };

    BENCHMARK("encrypt 1400-byte payload")
    {
        mdnspp::encrypted_packet_header hdr;
        hdr.sender_id = 1;
        hdr.sequence  = 1;
        return mdnspp::aead_encrypt(std::span<const std::byte, 32>(key), hdr, payload1400);
    };
}

TEST_CASE("Key rotation overhead", "[!benchmark][encrypt]")
{
    REQUIRE(mdnspp::init_crypto());

    auto key     = make_key();
    auto payload = make_payload();

    BENCHMARK("encrypt + rotate key each iteration")
    {
        mdnspp::encrypted_packet_header hdr;
        hdr.sender_id = 1;
        hdr.sequence  = 1;
        hdr.epoch     = 1;

        std::array<std::byte, 32> rotated_key{};
        rotated_key.fill(std::byte{0x99});

        auto encrypted = mdnspp::aead_encrypt(std::span<const std::byte, 32>(key), hdr, payload);
        auto decrypted = mdnspp::aead_decrypt(
            std::span<const std::byte, 32>(key),
            std::span<const std::byte>(encrypted));
        return decrypted;
    };
}
