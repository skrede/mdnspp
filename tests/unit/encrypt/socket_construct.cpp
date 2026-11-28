#include "helpers.h"
#include "aead_helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <array>
#include <cstddef>
#include <type_traits>
#include <system_error>

static_assert(mdnspp::socket_like<test_socket>,
    "encrypted_socket<mock_socket> must satisfy socket_like");

// Key state is mutex-guarded and the receive handler captures `this`.
static_assert(!std::is_move_constructible_v<test_socket>,
    "encrypted_socket must not be move-constructible");
static_assert(!std::is_move_assignable_v<test_socket>,
    "encrypted_socket must not be move-assignable");

namespace {

std::error_code construct_error(const mdnspp::encrypt::encrypt_socket_options &opts)
{
    mdnspp::testing::mock_executor ex;
    std::error_code ec;
    test_socket sock(ex, opts, ec);
    return ec;
}

mdnspp::encrypt::encrypt_socket_options zero_psk_opts()
{
    mdnspp::encrypt::encrypt_socket_options opts;
    opts.encrypt.sender_id = 1;
    return opts;
}

std::error_code send_error(test_socket &sock)
{
    std::error_code ec;
    sock.send(mdnspp::endpoint{}, std::span<const std::byte>(probe), ec);
    return ec;
}

void check_refuses_to_send(test_socket &sock)
{
    CHECK(send_error(sock) == std::make_error_code(std::errc::operation_not_permitted));
    CHECK_THROWS_AS(send_bytes(sock, probe), std::system_error);
    CHECK(sent_count(sock) == 0);
}

void check_never_delivers(test_socket &sock)
{
    const std::array<std::byte, 32> zero_key{};
    bool delivered = false;
    sock.async_receive([&delivered](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
    {
        delivered = true;
    });
    inject(sock, seal_packet(zero_key, make_header(1, 1, 0), probe));
    CHECK_FALSE(delivered);
}

std::error_code rotation_exception(test_socket &sock)
{
    try
    {
        rotate_key(sock, std::byte{0x43});
    }
    catch(const std::system_error &e)
    {
        return e.code();
    }
    return {};
}

std::error_code rotation_error(test_socket &sock, std::error_code ec = {})
{
    sock.update_key(make_key(std::byte{0x43}), ten_second_grace(), ec);
    return ec;
}

}

TEST_CASE("all-zero PSK sets invalid_argument in the error_code constructor", "[encrypted_socket][validate]")
{
    CHECK(construct_error(zero_psk_opts()) == std::make_error_code(std::errc::invalid_argument));
}

TEST_CASE("sender_id == 0 sets invalid_argument in the error_code constructor", "[encrypted_socket][validate]")
{
    auto opts = make_test_opts(std::byte{0x42}, 0);
    CHECK(construct_error(opts) == std::make_error_code(std::errc::invalid_argument));
}

TEST_CASE("replay_window_size == 0 sets invalid_argument in the error_code constructor",
    "[encrypted_socket][validate]")
{
    auto opts = make_test_opts();
    opts.encrypt.replay_window_size = 0;
    CHECK(construct_error(opts) == std::make_error_code(std::errc::invalid_argument));
}

TEST_CASE("a zero sender or session limit sets invalid_argument in the error_code constructor",
    "[encrypted_socket][validate]")
{
    auto senders = make_test_opts();
    senders.encrypt.max_senders = 0;
    auto sessions = make_test_opts();
    sessions.encrypt.max_sessions_per_sender = 0;
    CHECK(construct_error(senders) == std::make_error_code(std::errc::invalid_argument));
    CHECK(construct_error(sessions) == std::make_error_code(std::errc::invalid_argument));
}

TEST_CASE("throwing constructor throws std::system_error on an all-zero PSK", "[encrypted_socket][validate]")
{
    mdnspp::testing::mock_executor ex;
    auto opts = zero_psk_opts();

    CHECK_THROWS_AS((test_socket(ex, opts)), std::system_error);
}

TEST_CASE("throwing constructor throws std::system_error on sender_id == 0", "[encrypted_socket][validate]")
{
    mdnspp::testing::mock_executor ex;
    auto opts = make_test_opts(std::byte{0x42}, 0);

    CHECK_THROWS_AS((test_socket(ex, opts)), std::system_error);
}

TEST_CASE("valid options pass both constructors", "[encrypted_socket][validate]")
{
    CHECK_FALSE(construct_error(make_test_opts()));
}

TEST_CASE("a socket built from an executor alone refuses to send", "[encrypted_socket][unkeyed]")
{
    mdnspp::testing::mock_executor ex;
    std::error_code ec;
    test_socket plain(ex);
    test_socket with_ec(ex, ec);
    check_refuses_to_send(plain);
    check_refuses_to_send(with_ec);
}

TEST_CASE("a socket built from an executor alone never delivers a zero-key packet", "[encrypted_socket][unkeyed]")
{
    mdnspp::testing::mock_executor ex;
    test_socket sock(ex);
    check_never_delivers(sock);
}

TEST_CASE("a socket whose options failed validation refuses to send and receive", "[encrypted_socket][unkeyed]")
{
    mdnspp::testing::mock_executor ex;
    std::error_code ec;
    test_socket sock(ex, zero_psk_opts(), ec);
    REQUIRE(ec == std::make_error_code(std::errc::invalid_argument));
    check_refuses_to_send(sock);
    check_never_delivers(sock);
}

TEST_CASE("update_key does not make a socket without a usable key usable", "[encrypted_socket][unkeyed]")
{
    mdnspp::testing::mock_executor ex;
    std::error_code ec;
    test_socket bare(ex);
    test_socket invalid(ex, zero_psk_opts(), ec);
    CHECK(rotation_error(bare) == std::make_error_code(std::errc::operation_not_permitted));
    CHECK(rotation_error(invalid) == std::make_error_code(std::errc::operation_not_permitted));
    check_refuses_to_send(bare);
    check_refuses_to_send(invalid);
}

TEST_CASE("update_key with an error_code clears it and advances the epoch on a keyed socket",
    "[encrypted_socket][key_rotation]")
{
    mdnspp::testing::mock_executor ex;
    auto opts = make_test_opts();
    opts.encrypt.initial_epoch = 7;
    test_socket sock(ex, opts);
    CHECK_FALSE(rotation_error(sock, std::make_error_code(std::errc::io_error)));
    send_bytes(sock, probe);
    REQUIRE(sent_count(sock) == 1);
    CHECK(header_of(sent_packet_at(sock, 0)).epoch == 8);
}

TEST_CASE("update_key throws operation_not_permitted on a socket without a usable key", "[encrypted_socket][unkeyed]")
{
    mdnspp::testing::mock_executor ex;
    std::error_code ec;
    test_socket bare(ex);
    test_socket invalid(ex, zero_psk_opts(), ec);
    CHECK(rotation_exception(bare) == std::make_error_code(std::errc::operation_not_permitted));
    CHECK(rotation_exception(invalid) == std::make_error_code(std::errc::operation_not_permitted));
}
