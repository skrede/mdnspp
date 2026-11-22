#include "support/failure_injection.h"

#include "mdnspp/testing/mock_socket.h"
#include "mdnspp/testing/mock_executor.h"

#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <cstddef>
#include <system_error>

using mdnspp::endpoint;
using mdnspp::socket_options;
using mdnspp::testing::mock_socket;
using mdnspp::testing::mock_executor;
using mdnspp::test_support::failure_injection;

namespace {

template <typename F>
std::error_code thrown_by(F &&fn)
{
    try
    {
        fn();
    }
    catch(const std::system_error &e)
    {
        return e.code();
    }
    return std::error_code{};
}

const std::byte payload[] = {std::byte{0x01}, std::byte{0x02}};
const endpoint dest{"224.0.0.251", 5353};

}

TEST_CASE("the throwing constructors throw an injected construction failure", "[mock_socket][error_code]")
{
    const failure_injection injected{true, false};
    mock_executor ex;
    const socket_options opts{};
    REQUIRE(thrown_by([&] { const mock_socket sock{ex}; }) == std::errc::address_not_available);
    REQUIRE(thrown_by([&] { const mock_socket sock{ex, opts}; }) == std::errc::address_not_available);
}

TEST_CASE("the error_code constructors clear a stale error and report an injected failure", "[mock_socket][error_code]")
{
    mock_executor ex;
    const socket_options opts{};
    std::error_code ec = std::make_error_code(std::errc::io_error);
    const mock_socket plain{ex, ec};
    REQUIRE_FALSE(ec);
    ec = std::make_error_code(std::errc::io_error);
    const mock_socket with_opts{ex, opts, ec};
    REQUIRE_FALSE(ec);
    const failure_injection injected{true, false};
    const mock_socket failed_plain{ex, ec};
    REQUIRE(ec == std::errc::address_not_available);
    ec.clear();
    const mock_socket failed_with_opts{ex, opts, ec};
    REQUIRE(ec == std::errc::address_not_available);
}

TEST_CASE("the throwing send throws an injected send failure and records nothing", "[mock_socket][error_code]")
{
    mock_executor ex;
    mock_socket sock{ex};
    const failure_injection injected{false, true};
    REQUIRE(thrown_by([&] { sock.send(dest, std::span<const std::byte>{payload}); }) == std::errc::network_unreachable);
    REQUIRE(sock.sent_packets().empty());
}

TEST_CASE("the throwing send records the packet as the error_code send does", "[mock_socket][error_code]")
{
    mock_executor ex;
    mock_socket sock{ex};
    std::error_code ec = std::make_error_code(std::errc::io_error);
    sock.send(dest, std::span<const std::byte>{payload}, ec);
    REQUIRE_FALSE(ec);
    REQUIRE_NOTHROW(sock.send(dest, std::span<const std::byte>{payload}));
    REQUIRE(sock.sent_packets().size() == 2);
    REQUIRE(sock.sent_packets()[1].dest == sock.sent_packets()[0].dest);
    REQUIRE(sock.sent_packets()[1].data == sock.sent_packets()[0].data);
}
