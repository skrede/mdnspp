#include "mdnspp/encrypt/aead.h"
#include "mdnspp/encrypt/packet_header.h"

#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>

#include <span>
#include <array>
#include <vector>
#include <cstddef>
#include <cstdint>
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

mdnspp::encrypt::encrypted_packet_header make_header()
{
    mdnspp::encrypt::encrypted_packet_header hdr;
    hdr.sender_id = 1;
    hdr.sequence  = 1;
    return hdr;
}

std::size_t encrypt_into(const std::array<std::byte, 32> &key, std::span<const std::byte> payload,
                         std::vector<std::byte> &out)
{
    std::size_t written = 0;
    mdnspp::encrypt::aead_encrypt(std::span<const std::byte, 32>(key), make_header(), payload, out, written);
    return written;
}

std::size_t decrypt_into(const std::array<std::byte, 32> &key, std::span<const std::byte> packet,
                         std::vector<std::byte> &out)
{
    std::size_t written = 0;
    mdnspp::encrypt::aead_decrypt(std::span<const std::byte, 32>(key), packet, out, written);
    return written;
}

std::vector<std::byte> buffer_for(std::size_t payload_size)
{
    return std::vector<std::byte>(payload_size + mdnspp::encrypt::encrypted_overhead);
}

std::vector<std::byte> cleartext_copy(const std::vector<std::byte> &payload)
{
    std::vector<std::byte> dst(payload.size());
    std::memcpy(dst.data(), payload.data(), payload.size());
    return dst;
}

}

TEST_CASE("Encrypt benchmark smoke test", "[encrypt]")
{
    REQUIRE(mdnspp::encrypt::init_crypto());

    auto key = make_key();
    auto payload = make_payload(200);
    auto packet = buffer_for(payload.size());

    const std::size_t sealed = encrypt_into(key, payload, packet);
    REQUIRE(sealed == payload.size() + mdnspp::encrypt::encrypted_overhead);

    std::vector<std::byte> decrypted(payload.size());
    const std::size_t opened = decrypt_into(key, std::span<const std::byte>(packet.data(), sealed), decrypted);

    REQUIRE(opened == payload.size());
    REQUIRE(std::ranges::equal(decrypted, payload));
}

TEST_CASE("Cleartext baseline throughput", "[!benchmark][encrypt]")
{
    auto payload64   = make_payload(64);
    auto payload200  = make_payload(200);
    auto payload512  = make_payload(512);
    auto payload1400 = make_payload(1400);

    BENCHMARK("cleartext copy 64-byte payload") { return cleartext_copy(payload64); };
    BENCHMARK("cleartext copy 200-byte payload") { return cleartext_copy(payload200); };
    BENCHMARK("cleartext copy 512-byte payload") { return cleartext_copy(payload512); };
    BENCHMARK("cleartext copy 1400-byte payload") { return cleartext_copy(payload1400); };
}

TEST_CASE("Encrypt throughput", "[!benchmark][encrypt]")
{
    REQUIRE(mdnspp::encrypt::init_crypto());

    auto key     = make_key();
    auto payload = make_payload();
    auto out     = buffer_for(payload.size());

    BENCHMARK("encrypt 200-byte payload")
    {
        return encrypt_into(key, payload, out);
    };
}

TEST_CASE("Decrypt throughput", "[!benchmark][encrypt]")
{
    REQUIRE(mdnspp::encrypt::init_crypto());

    auto key     = make_key();
    auto payload = make_payload();
    auto packet  = buffer_for(payload.size());
    auto out     = std::vector<std::byte>(payload.size());
    const std::size_t sealed = encrypt_into(key, payload, packet);
    const std::span<const std::byte> wire(packet.data(), sealed);

    BENCHMARK("decrypt 200-byte payload")
    {
        return decrypt_into(key, wire, out);
    };
}

TEST_CASE("Encrypt varying payload sizes", "[!benchmark][encrypt]")
{
    REQUIRE(mdnspp::encrypt::init_crypto());

    auto key         = make_key();
    auto payload64   = make_payload(64);
    auto payload512  = make_payload(512);
    auto payload1400 = make_payload(1400);
    auto out64       = buffer_for(64);
    auto out512      = buffer_for(512);
    auto out1400     = buffer_for(1400);

    BENCHMARK("encrypt 64-byte payload") { return encrypt_into(key, payload64, out64); };
    BENCHMARK("encrypt 512-byte payload") { return encrypt_into(key, payload512, out512); };
    BENCHMARK("encrypt 1400-byte payload") { return encrypt_into(key, payload1400, out1400); };
}

TEST_CASE("Key rotation overhead", "[!benchmark][encrypt]")
{
    REQUIRE(mdnspp::encrypt::init_crypto());

    auto key     = make_key();
    auto payload = make_payload();
    auto packet  = buffer_for(payload.size());
    auto out     = std::vector<std::byte>(payload.size());

    BENCHMARK("encrypt + rotate key each iteration")
    {
        const std::size_t sealed = encrypt_into(key, payload, packet);
        return decrypt_into(key, std::span<const std::byte>(packet.data(), sealed), out);
    };
}
