#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <vector>

TEST_CASE("send encrypts plaintext and forwards to inner socket", "[encrypted_socket][send]")
{
    paired_sockets pair;
    plain_bytes plaintext{std::byte{0xDE}, std::byte{0xAD}};
    send_bytes(pair.sender, plaintext);

    CHECK(sent_count(pair.sender) == 1);
    const auto &pkt = pair.sender.inner().sent_packets()[0].data;
    CHECK(pkt.size() == plaintext.size() + mdnspp::encrypt::encrypted_overhead);
    CHECK(pkt[0] == std::byte{0x4D});
    CHECK(pkt[1] == std::byte{0x43});
}

TEST_CASE("send increments sequence counter", "[encrypted_socket][sequence]")
{
    paired_sockets pair;
    plain_bytes plaintext{std::byte{0xAB}};
    for(std::size_t i = 0; i < 3; ++i)
        send_bytes(pair.sender, plaintext);

    REQUIRE(sent_count(pair.sender) == 3);

    // The counter starts at a per-boot randomized base (top 24 bits random,
    // low 40 bits zero) and increments by one per packet.
    constexpr uint64_t low40_mask = (uint64_t{1} << 40) - 1;
    auto hdr0 = header_of(sent_packet_at(pair.sender, 0));
    CHECK((hdr0.sequence & low40_mask) == 1);

    for(std::size_t i = 0; i < 3; ++i)
        CHECK(header_of(sent_packet_at(pair.sender, i)).sequence == hdr0.sequence + i);
}

TEST_CASE("sequence counter start is randomized per socket", "[encrypted_socket][sequence]")
{
    paired_sockets pair;
    plain_bytes plaintext{std::byte{0x01}};
    send_bytes(pair.sender, plaintext);
    send_bytes(pair.receiver, plaintext);

    auto hdr_a = header_of(sent_packet_at(pair.sender, 0));
    auto hdr_b = header_of(sent_packet_at(pair.receiver, 0));

    // Independent CSPRNG draws of the top 24 bits collide with probability 2^-24.
    CHECK(hdr_a.sequence != hdr_b.sequence);
}
