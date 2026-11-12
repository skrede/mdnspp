#include "mdnspp/asio/asio_policy.h"
#include "mdnspp/policy.h"
#include "mdnspp/socket_options.h"

#include "support/skip_or_fail.h"

#include <catch2/catch_test_macros.hpp>

#include <string>

static_assert(mdnspp::policy_like<mdnspp::asio_policy>, "asio_policy must satisfy policy_like — check asio_socket/asio_timer constructor signatures");
static_assert(mdnspp::socket_like<mdnspp::asio_socket>, "asio_socket must satisfy socket_like — check async_receive/send/close signatures");
static_assert(mdnspp::timer_like<mdnspp::asio_timer>, "asio_timer must satisfy timer_like — check expires_after/async_wait/cancel signatures");
static_assert(std::constructible_from<mdnspp::asio_socket, asio::io_context&, const mdnspp::socket_options&>,
              "asio_socket must be constructible from (io_context, socket_options)");
static_assert(std::constructible_from<mdnspp::asio_socket, asio::io_context&, const mdnspp::socket_options&, std::error_code&>,
              "asio_socket must be constructible from (io_context, socket_options, error_code)");

TEST_CASE("asio_policy satisfies policy_like concept (compile-time)", "[concept][conformance][asio]")
{
    SUCCEED("asio_policy static_assert passed at compile time");
}

TEST_CASE("asio_socket satisfies socket_like concept", "[concept][conformance][asio]")
{
    asio::io_context io;
    // Construction joins multicast group — fails without a usable network interface.
    try
    {
        mdnspp::asio_socket socket{io};
        SUCCEED("asio_socket constructed and multicast group joined");
    }
    catch(const std::exception &e)
    {
        mdnspp::test_support::skip_or_fail(std::string{"asio_socket construction failed: "} + e.what());
    }
}

TEST_CASE("asio_timer satisfies timer_like concept", "[concept][conformance][asio]")
{
    asio::io_context io;
    mdnspp::asio_timer timer{io};
    timer.expires_after(std::chrono::milliseconds{100});
    timer.cancel();
    SUCCEED("asio_timer methods callable");
}

TEST_CASE("asio_socket with default socket_options", "[concept][conformance][asio][socket_options]")
{
    asio::io_context io;
    try
    {
        mdnspp::socket_options opts{};
        mdnspp::asio_socket socket{io, opts};
        SUCCEED("asio_socket constructed with default socket_options (INADDR_ANY, TTL=255)");
    }
    catch(const std::exception &e)
    {
        mdnspp::test_support::skip_or_fail(std::string{"asio_socket construction with socket_options failed: "} + e.what());
    }
}

TEST_CASE("asio_socket with socket_options error_code overload", "[concept][conformance][asio][socket_options]")
{
    asio::io_context io;
    mdnspp::socket_options opts{};
    std::error_code ec;
    mdnspp::asio_socket socket{io, opts, ec};
    if(ec)
        mdnspp::test_support::skip_or_fail("asio_socket non-throwing construction with socket_options failed: " + ec.message());
    else
        SUCCEED("asio_socket constructed with default socket_options via error_code overload");
}
