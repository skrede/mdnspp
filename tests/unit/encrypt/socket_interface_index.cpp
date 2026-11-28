#include "helpers.h"

#include "support/skip_or_fail.h"
#include "support/ipv6_interface.h"

#include "mdnspp/network_interface.h"

#include "mdnspp/inproc/inproc_socket.h"

#include "mdnspp/default/default_socket.h"
#include "mdnspp/default/default_context.h"

#include "mdnspp/detail/transport_traits.h"

#if defined(MDNSPP_HAS_ASIO)
#include "mdnspp/asio/asio_socket.h"

#include <asio.hpp>
#endif

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <system_error>

using mdnspp::encrypt::encrypted_socket;
using mdnspp::detail::reports_interface_index;

static_assert(!reports_interface_index<encrypted_socket<mdnspp::inproc::inproc_socket<>>>,
              "an encrypted socket reports an interface index only when its inner socket does");

namespace {

mdnspp::encrypt::encrypt_socket_options loopback_options(uint32_t index)
{
    mdnspp::encrypt::encrypt_socket_options opts = make_test_opts();
    static_cast<mdnspp::socket_options &>(opts) = mdnspp::test_support::ipv6_group_options();
    opts.interface_index = index;
    return opts;
}

}

TEST_CASE("encrypted_socket reports the interface index of an inner mock socket", "[encrypt][socket]")
{
    mdnspp::testing::mock_executor ex;
    mdnspp::encrypt::encrypt_socket_options opts = make_test_opts();
    opts.interface_index = 7;
    test_socket sock{ex, opts};
    CHECK(sock.interface_index() == 7);
}

TEST_CASE("encrypted_socket reports the interface index of an inner default_socket", "[encrypt][socket]")
{
    const uint32_t loopback = mdnspp::test_support::loopback_ipv6_interface().index;
    mdnspp::default_context ctx;
    std::error_code ec;
    encrypted_socket<mdnspp::default_socket> sock{ctx, loopback_options(loopback), ec};
    if(ec)
        mdnspp::test_support::skip_or_fail("IPv6 default_socket construction on loopback failed: " + ec.message());
    CHECK(sock.interface_index() == loopback);
}

#if defined(MDNSPP_HAS_ASIO)
TEST_CASE("encrypted_socket reports the interface index of an inner asio_socket", "[encrypt][socket][asio]")
{
    const uint32_t loopback = mdnspp::test_support::loopback_ipv6_interface().index;
    asio::io_context io;
    std::error_code ec;
    encrypted_socket<mdnspp::asio_socket> sock{io, loopback_options(loopback), ec};
    if(ec)
        mdnspp::test_support::skip_or_fail("IPv6 asio_socket construction on loopback failed: " + ec.message());
    CHECK(sock.interface_index() == loopback);
}
#endif
