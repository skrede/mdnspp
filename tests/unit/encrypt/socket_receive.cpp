#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>

namespace {

using mdnspp::encrypt::cleartext_detection;

plain_bytes cleartext_packet()
{
    return {std::byte{0x00}, std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
}

plain_bytes small_cleartext_packet()
{
    plain_bytes packet(28, std::byte{0x00});
    packet[2] = std::byte{0x01};
    return packet;
}

received_packet receive_cleartext(const plain_bytes &packet, bool accept_cleartext, cleartext_detection detection)
{
    mdnspp::testing::mock_executor ex;
    auto opts = make_test_opts();
    opts.encrypt.accept_cleartext = accept_cleartext;
    opts.encrypt.detection = detection;
    test_socket sock(ex, opts);
    sock.inner().enqueue(packet);
    return receive_one(sock);
}

}

TEST_CASE("async_receive decrypts valid packet and calls handler", "[encrypted_socket][receive]")
{
    paired_sockets pair;
    plain_bytes plaintext{std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
    send_bytes(pair.sender, plaintext);

    REQUIRE(sent_count(pair.sender) == 1);
    pair.receiver.inner().enqueue(sent_packet_at(pair.sender, 0));
    auto result = receive_one(pair.receiver);

    CHECK(result.called);
    CHECK(result.data == plaintext);
}

TEST_CASE("recv_metadata forwarded unchanged", "[encrypted_socket][metadata]")
{
    paired_sockets pair;
    send_bytes(pair.sender, plain_bytes{std::byte{0xFF}});

    pair.receiver.inner().enqueue(sent_packet_at(pair.sender, 0),
                                  mdnspp::endpoint{"1.2.3.4", 5353},
                                  std::optional<uint8_t>{uint8_t{128}});
    auto result = receive_one(pair.receiver);

    CHECK(result.meta.ttl == std::optional<uint8_t>{uint8_t{128}});
    CHECK(result.meta.sender.address == "1.2.3.4");
}

TEST_CASE("magic_byte detection passes cleartext through when accept_cleartext is set",
    "[encrypted_socket][cleartext]")
{
    CHECK(receive_cleartext(cleartext_packet(), true, cleartext_detection::magic_byte).called);
}

TEST_CASE("magic_byte detection drops cleartext when accept_cleartext is unset", "[encrypted_socket][cleartext]")
{
    CHECK_FALSE(receive_cleartext(cleartext_packet(), false, cleartext_detection::magic_byte).called);
}

TEST_CASE("cleartext_detection::reject_all drops all non-encrypted",
    "[encrypted_socket][cleartext][reject_all]")
{
    // even with accept_cleartext=true, reject_all wins
    CHECK_FALSE(receive_cleartext(cleartext_packet(), true, cleartext_detection::reject_all).called);
}

TEST_CASE("attempt_decrypt delivers cleartext shorter than the encrypted header when accepted",
    "[encrypted_socket][cleartext][attempt_decrypt]")
{
    // A legitimate cleartext mDNS query can be ~28 bytes, below
    // encrypted_header_size. It must still be deliverable under
    // attempt_decrypt with accept_cleartext = true.
    auto small_cleartext = small_cleartext_packet();
    auto result = receive_cleartext(small_cleartext, true, cleartext_detection::attempt_decrypt);

    CHECK(result.called);
    CHECK(result.data == small_cleartext);
}

TEST_CASE("attempt_decrypt drops short cleartext when accept_cleartext is unset",
    "[encrypted_socket][cleartext][attempt_decrypt]")
{
    CHECK_FALSE(receive_cleartext(small_cleartext_packet(), false, cleartext_detection::attempt_decrypt).called);
}

TEST_CASE("reject_all drops short cleartext regardless of accept_cleartext",
    "[encrypted_socket][cleartext][attempt_decrypt]")
{
    CHECK_FALSE(receive_cleartext(small_cleartext_packet(), true, cleartext_detection::reject_all).called);
}

TEST_CASE("corrupted auth tag silently dropped", "[encrypted_socket][tamper]")
{
    paired_sockets pair;
    send_bytes(pair.sender, plain_bytes{std::byte{0x55}, std::byte{0x66}});

    auto corrupted = sent_packet_at(pair.sender, 0);
    REQUIRE_FALSE(corrupted.empty());
    if(!corrupted.empty())
        corrupted.back() ^= std::byte{0xFF};
    pair.receiver.inner().enqueue(corrupted);

    CHECK_FALSE(receive_one(pair.receiver).called);
}

TEST_CASE("replayed sequence silently dropped", "[encrypted_socket][replay]")
{
    paired_sockets pair;
    send_bytes(pair.sender, plain_bytes{std::byte{0xAA}});
    auto encrypted_pkt = sent_packet_at(pair.sender, 0);

    pair.receiver.inner().enqueue(encrypted_pkt);
    CHECK(receive_one(pair.receiver).called);

    pair.receiver.inner().enqueue(encrypted_pkt);
    CHECK_FALSE(receive_one(pair.receiver).called);
}
