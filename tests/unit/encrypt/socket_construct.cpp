#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

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
