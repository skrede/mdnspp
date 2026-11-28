#include "helpers.h"

#include "mdnspp/encrypt/key_ring.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <thread>
#include <cstddef>
#include <optional>

namespace {

plain_bytes first_epoch_packet(paired_sockets &pair, std::byte payload_byte)
{
    send_bytes(pair.sender, plain_bytes{payload_byte});
    REQUIRE(sent_count(pair.sender) == 1);
    return sent_packet_at(pair.sender, 0);
}

}

TEST_CASE("previous epoch packets accepted during grace window", "[encrypted_socket][key_rotation][grace]")
{
    paired_sockets pair;
    plain_bytes plaintext{std::byte{0xAB}, std::byte{0xCD}};
    send_bytes(pair.sender, plaintext);

    REQUIRE(sent_count(pair.sender) == 1);
    auto epoch0_pkt = sent_packet_at(pair.sender, 0);
    rotate_key(pair.receiver, std::byte{0x43});

    pair.receiver.inner().enqueue(epoch0_pkt);
    auto result = receive_one(pair.receiver);

    CHECK(result.called);
    CHECK(result.data == plaintext);
}

TEST_CASE("unknown epoch packets rejected immediately", "[encrypted_socket][key_rotation][grace]")
{
    paired_sockets pair;
    auto epoch0_pkt = first_epoch_packet(pair, std::byte{0x77});

    rotate_key(pair.receiver, std::byte{0x43});
    rotate_key(pair.receiver, std::byte{0x44});

    pair.receiver.inner().enqueue(epoch0_pkt);
    CHECK_FALSE(receive_one(pair.receiver).called);
}

TEST_CASE("time-based grace expiry drops previous epoch packets", "[encrypted_socket][key_rotation][grace]")
{
    using namespace std::chrono_literals;

    paired_sockets pair;
    auto epoch0_pkt = first_epoch_packet(pair, std::byte{0x55});

    rotate_key(pair.receiver, std::byte{0x43},
               mdnspp::encrypt::grace_period{.duration = 1ms, .packet_count = std::nullopt});
    std::this_thread::sleep_for(5ms);

    pair.receiver.inner().enqueue(epoch0_pkt);
    CHECK_FALSE(receive_one(pair.receiver).called);
}

TEST_CASE("count-based grace expiry drops previous epoch packets after limit",
    "[encrypted_socket][key_rotation][grace]")
{
    paired_sockets pair;
    for(auto byte_value : {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}})
        send_bytes(pair.sender, plain_bytes{byte_value});
    REQUIRE(sent_count(pair.sender) == 3);

    rotate_key(pair.receiver, std::byte{0x43},
               mdnspp::encrypt::grace_period{.duration = std::nullopt, .packet_count = 2});

    pair.receiver.inner().enqueue(sent_packet_at(pair.sender, 0));
    CHECK(receive_one(pair.receiver).called);
    pair.receiver.inner().enqueue(sent_packet_at(pair.sender, 1));
    CHECK(receive_one(pair.receiver).called);
    pair.receiver.inner().enqueue(sent_packet_at(pair.sender, 2));
    CHECK_FALSE(receive_one(pair.receiver).called);
}

TEST_CASE("update_key with an empty grace_period applies the default duration bound",
    "[encrypted_socket][key_rotation][grace]")
{
    paired_sockets pair;
    auto epoch0_pkt = first_epoch_packet(pair, std::byte{0x99});

    // Neither duration nor packet_count set: default_grace_duration (30 s)
    // bounds the window instead of leaving the previous key accepted forever.
    rotate_key(pair.receiver, std::byte{0x43}, mdnspp::encrypt::grace_period{});

    pair.receiver.inner().enqueue(epoch0_pkt);

    CHECK(receive_one(pair.receiver).called);
}

TEST_CASE("an expired previous key is zeroized on the next send-key lookup", "[key_ring][key_rotation][grace]")
{
    using namespace std::chrono_literals;

    const mdnspp::encrypt::secure_key initial = make_key(std::byte{0x42});
    mdnspp::encrypt::key_ring ring(initial.bytes(), 0);
    REQUIRE_FALSE(ring.update(make_key(std::byte{0x43}), {.duration = 0ns, .packet_count = {}}));
    REQUIRE(ring.has_previous_key());

    const auto key = ring.key_for_send();
    REQUIRE(key.has_value());
    CHECK(key->epoch == 1);
    CHECK_FALSE(ring.has_previous_key());
}
