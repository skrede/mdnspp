#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>

namespace {

mdnspp::encrypt::encrypt_socket_options epoch_opts(std::byte fill, uint32_t sender_id, uint32_t initial_epoch)
{
    auto opts = make_test_opts(fill, sender_id);
    opts.encrypt.initial_epoch = initial_epoch;
    return opts;
}

}

TEST_CASE("initial_epoch is stamped on sent packets and accepted by matching peers",
    "[encrypted_socket][key_rotation][initial_epoch]")
{
    paired_sockets pair(epoch_opts(std::byte{0x42}, 1, 5), epoch_opts(std::byte{0x42}, 2, 5));
    plain_bytes plaintext{std::byte{0x10}, std::byte{0x20}};
    send_bytes(pair.sender, plaintext);

    REQUIRE(sent_count(pair.sender) == 1);
    CHECK(header_of(sent_packet_at(pair.sender, 0)).epoch == 5);

    pair.receiver.inner().enqueue(sent_packet_at(pair.sender, 0));
    auto result = receive_one(pair.receiver);

    CHECK(result.called);
    CHECK(result.data == plaintext);
}

TEST_CASE("restarted peer provisioned with the rotated key and epoch rejoins",
    "[encrypted_socket][key_rotation][initial_epoch]")
{
    // Receiver was present for the rotation epoch 0 -> 1. The restarted
    // sender missed it; it is provisioned with the current group key and
    // initial_epoch = 1 and rejoins immediately.
    paired_sockets pair(epoch_opts(std::byte{0x43}, 1, 1), make_test_opts(std::byte{0x42}, 2));
    rotate_key(pair.receiver, std::byte{0x43});

    plain_bytes plaintext{std::byte{0xAA}, std::byte{0xBB}};
    send_bytes(pair.sender, plaintext);

    REQUIRE(sent_count(pair.sender) == 1);
    pair.receiver.inner().enqueue(sent_packet_at(pair.sender, 0));
    auto result = receive_one(pair.receiver);

    CHECK(result.called);
    CHECK(result.data == plaintext);
}

TEST_CASE("packets one epoch ahead with the same key material are accepted",
    "[encrypted_socket][key_rotation][epoch_ahead]")
{
    // The sender's epoch counter runs one ahead of the receiver's (e.g. it
    // was provisioned with a skewed initial_epoch mid-rotation) while both
    // hold the same key. The receiver tries its current key for epoch + 1.
    paired_sockets pair(epoch_opts(std::byte{0x42}, 1, 1), make_test_opts(std::byte{0x42}, 2));
    plain_bytes plaintext{std::byte{0x5A}};
    send_bytes(pair.sender, plaintext);

    REQUIRE(sent_count(pair.sender) == 1);
    pair.receiver.inner().enqueue(sent_packet_at(pair.sender, 0));
    auto result = receive_one(pair.receiver);

    CHECK(result.called);
    CHECK(result.data == plaintext);
}

TEST_CASE("packets one epoch ahead under a different key are rejected",
    "[encrypted_socket][key_rotation][epoch_ahead]")
{
    paired_sockets pair(epoch_opts(std::byte{0x43}, 1, 1), make_test_opts(std::byte{0x42}, 2));
    send_bytes(pair.sender, plain_bytes{std::byte{0x5B}});

    REQUIRE(sent_count(pair.sender) == 1);
    pair.receiver.inner().enqueue(sent_packet_at(pair.sender, 0));

    CHECK_FALSE(receive_one(pair.receiver).called);
}
