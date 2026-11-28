#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>

namespace {

mdnspp::encrypt::encrypt_socket_options auth_only_sender_opts(uint32_t sender_id = 1)
{
    auto opts = make_test_opts(std::byte{0x42}, sender_id);
    opts.encrypt.auth_only = true;
    return opts;
}

mdnspp::encrypt::encrypt_socket_options receiver_opts(mdnspp::encrypt::receive_mode mode)
{
    auto opts = make_test_opts(std::byte{0x42}, 2);
    opts.encrypt.recv_mode = mode;
    return opts;
}

}

TEST_CASE("Auth-only: received payload matches sent plaintext", "[encrypted_socket][auth_only]")
{
    paired_sockets pair(auth_only_sender_opts(), make_test_opts(std::byte{0x42}, 2));
    plain_bytes plaintext{std::byte{0xDE}, std::byte{0xAD}, std::byte{0xBE}, std::byte{0xEF}};
    send_bytes(pair.sender, plaintext);

    REQUIRE(sent_count(pair.sender) == 1);
    auto sent_data = sent_packet_at(pair.sender, 0);
    CHECK(header_of(sent_data).flags == 0);

    pair.receiver.inner().enqueue(sent_data);
    auto result = receive_one(pair.receiver);

    CHECK(result.called);
    CHECK(result.data == plaintext);
}

TEST_CASE("Auth-only: tampered payload dropped", "[encrypted_socket][auth_only][tamper]")
{
    paired_sockets pair(auth_only_sender_opts(), make_test_opts(std::byte{0x42}, 2));
    send_bytes(pair.sender, plain_bytes{std::byte{0xCA}, std::byte{0xFE}});

    REQUIRE(sent_count(pair.sender) == 1);
    auto tampered = sent_packet_at(pair.sender, 0);
    tampered[mdnspp::encrypt::encrypted_header_size] ^= std::byte{0xFF};
    pair.receiver.inner().enqueue(tampered);

    CHECK_FALSE(receive_one(pair.receiver).called);
}

TEST_CASE("receive_mode::encrypted_only drops auth-only packets", "[encrypted_socket][receive_mode]")
{
    paired_sockets pair(auth_only_sender_opts(), receiver_opts(mdnspp::encrypt::receive_mode::encrypted_only));
    send_bytes(pair.sender, plain_bytes{std::byte{0x11}});

    REQUIRE(sent_count(pair.sender) == 1);
    pair.receiver.inner().enqueue(sent_packet_at(pair.sender, 0));

    CHECK_FALSE(receive_one(pair.receiver).called);
}

TEST_CASE("receive_mode::auth_only drops encrypted packets", "[encrypted_socket][receive_mode]")
{
    paired_sockets pair(make_test_opts(std::byte{0x42}, 1), receiver_opts(mdnspp::encrypt::receive_mode::auth_only));
    send_bytes(pair.sender, plain_bytes{std::byte{0x22}});

    REQUIRE(sent_count(pair.sender) == 1);
    pair.receiver.inner().enqueue(sent_packet_at(pair.sender, 0));

    CHECK_FALSE(receive_one(pair.receiver).called);
}

TEST_CASE("receive_mode::accept_both accepts both encrypted and auth-only", "[encrypted_socket][receive_mode]")
{
    paired_sockets pair(make_test_opts(std::byte{0x42}, 1), receiver_opts(mdnspp::encrypt::receive_mode::accept_both));
    test_socket ao_sender(pair.ex, auth_only_sender_opts(3));
    plain_bytes plaintext{std::byte{0x33}};

    send_bytes(pair.sender, plaintext);
    send_bytes(ao_sender, plaintext);

    REQUIRE(sent_count(pair.sender) == 1);
    REQUIRE(sent_count(ao_sender) == 1);

    pair.receiver.inner().enqueue(sent_packet_at(pair.sender, 0));
    pair.receiver.inner().enqueue(sent_packet_at(ao_sender, 0));

    int handler_count = 0;
    handler_count += receive_one(pair.receiver).called;
    handler_count += receive_one(pair.receiver).called;

    CHECK(handler_count == 2);
}
