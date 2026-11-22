#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <thread>
#include <cstddef>

namespace {

std::size_t deliver_all_sent(paired_sockets &pair, std::size_t count)
{
    std::size_t delivered = 0;
    for(std::size_t i = 0; i < count; ++i)
    {
        pair.receiver.inner().enqueue(sent_packet_at(pair.sender, i));
        delivered += receive_one(pair.receiver).called;
    }
    return delivered;
}

// Key state is mutex-guarded; rotating from another thread while the main
// thread drains the receive queue must be free of data races (epoch-0 packets
// remain decryptable via the grace window).
std::thread rotate_from_other_thread(test_socket &sock)
{
    using namespace std::chrono_literals;
    return std::thread{[&sock]
    {
        std::this_thread::sleep_for(1ms);
        rotate_key(sock, std::byte{0x43});
    }};
}

}

TEST_CASE("epoch field reflects current epoch in sent packets", "[encrypted_socket][key_rotation]")
{
    mdnspp::testing::mock_executor ex;
    test_socket sender(ex, make_test_opts(std::byte{0x42}, 1));
    plain_bytes plaintext{std::byte{0x01}};

    send_bytes(sender, plaintext);
    REQUIRE(sent_count(sender) == 1);
    CHECK(header_of(sent_packet_at(sender, 0)).epoch == 0);

    rotate_key(sender, std::byte{0x43});
    send_bytes(sender, plaintext);
    REQUIRE(sent_count(sender) == 2);
    CHECK(header_of(sent_packet_at(sender, 1)).epoch == 1);

    rotate_key(sender, std::byte{0x44});
    send_bytes(sender, plaintext);
    REQUIRE(sent_count(sender) == 3);
    CHECK(header_of(sent_packet_at(sender, 2)).epoch == 2);
}

TEST_CASE("update_key bumps epoch and encrypts with new key", "[encrypted_socket][key_rotation]")
{
    paired_sockets pair;
    plain_bytes plaintext{std::byte{0xBE}, std::byte{0xEF}};

    send_bytes(pair.sender, plaintext);
    REQUIRE(sent_count(pair.sender) == 1);
    CHECK(header_of(sent_packet_at(pair.sender, 0)).epoch == 0);
    CHECK(receive_packet(pair.receiver, sent_packet_at(pair.sender, 0)).called);

    rotate_key(pair.sender, std::byte{0x43});
    test_socket receiver2(pair.ex, make_test_opts(std::byte{0x42}, 3));
    rotate_key(receiver2, std::byte{0x43});

    send_bytes(pair.sender, plaintext);
    REQUIRE(sent_count(pair.sender) == 2);
    CHECK(header_of(sent_packet_at(pair.sender, 1)).epoch == 1);

    auto result = receive_packet(receiver2, sent_packet_at(pair.sender, 1));
    CHECK(result.called);
    CHECK(result.data == plaintext);
}

TEST_CASE("cross-thread update_key during receive traffic is well-defined", "[encrypted_socket][key_rotation]")
{
    paired_sockets pair;
    plain_bytes plaintext{std::byte{0x01}};
    constexpr std::size_t packet_count = 200;
    for(std::size_t i = 0; i < packet_count; ++i)
        send_bytes(pair.sender, plaintext);
    REQUIRE(sent_count(pair.sender) == packet_count);

    auto rotation_thread = rotate_from_other_thread(pair.receiver);
    auto delivered = deliver_all_sent(pair, packet_count);
    rotation_thread.join();
    CHECK(delivered == packet_count);
}
