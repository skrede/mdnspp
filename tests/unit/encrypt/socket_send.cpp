#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <cstddef>
#include <cstdint>
#include <system_error>

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

namespace {

plain_bytes largest_plaintext()
{
    return plain_bytes(mdnspp::detail::max_udp_payload - mdnspp::encrypt::encrypted_overhead, std::byte{0x5A});
}

}

TEST_CASE("send of the largest plaintext fills one datagram and arrives intact", "[encrypted_socket][send]")
{
    paired_sockets pair;
    payloads got;
    arm_collecting(pair.receiver, got);
    std::error_code ec;
    const auto plaintext = largest_plaintext();

    pair.sender.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext), ec);

    REQUIRE_FALSE(ec);
    CHECK(sent_packet_at(pair.sender, 0).size() == mdnspp::detail::max_udp_payload);
    inject(pair.receiver, sent_packet_at(pair.sender, 0));
    CHECK(got == payloads{plaintext});
}

TEST_CASE("send of one byte more than fits reports buffer_too_small and sends nothing", "[encrypted_socket][send]")
{
    paired_sockets pair;
    auto plaintext = largest_plaintext();
    plaintext.push_back(std::byte{0x5A});
    std::error_code ec;

    pair.sender.send(mdnspp::endpoint{}, std::span<const std::byte>(plaintext), ec);

    CHECK(ec == mdnspp::encrypt::encrypt_error::buffer_too_small);
    CHECK(sent_count(pair.sender) == 0);
}

TEST_CASE("throwing send carries the same buffer_too_small code and sends nothing", "[encrypted_socket][send]")
{
    paired_sockets pair;
    auto plaintext = largest_plaintext();
    plaintext.push_back(std::byte{0x5A});

    try
    {
        send_bytes(pair.sender, plaintext);
        FAIL("expected std::system_error");
    }
    catch(const std::system_error &e)
    {
        CHECK(e.code() == mdnspp::encrypt::encrypt_error::buffer_too_small);
    }
    CHECK(sent_count(pair.sender) == 0);
}
