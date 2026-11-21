#include "mdnspp/inproc/inproc_bus.h"
#include "mdnspp/inproc/inproc_socket.h"
#include "mdnspp/inproc/inproc_executor.h"
#include "mdnspp/inproc/inproc_socket_options.h"

#include "mdnspp/endpoint.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <cstddef>
#include <system_error>

using mdnspp::endpoint;
using mdnspp::inproc::inproc_bus;
using mdnspp::inproc::inproc_socket;
using mdnspp::inproc::inproc_executor;
using mdnspp::inproc::inproc_socket_options;

namespace {

const std::byte payload[] = {std::byte{0x01}, std::byte{0x02}};
const endpoint dest{"224.0.0.251", 5353};

std::error_code send_exception(inproc_socket<> &sock)
{
    try
    {
        sock.send(dest, std::span<const std::byte>{payload});
    }
    catch(const std::system_error &e)
    {
        return e.code();
    }
    return {};
}

}

TEST_CASE("the error_code constructors clear a stale error", "[inproc_socket][error_code]")
{
    inproc_bus<> bus;
    inproc_executor<> ex{bus};
    std::error_code ec = std::make_error_code(std::errc::io_error);
    const inproc_socket<> plain{ex, ec};
    REQUIRE_FALSE(ec);
    ec = std::make_error_code(std::errc::io_error);
    const inproc_socket<> with_opts{ex, inproc_socket_options{}, ec};
    REQUIRE_FALSE(ec);
}

TEST_CASE("the error_code send clears a stale error and queues the datagram", "[inproc_socket][error_code]")
{
    inproc_bus<> bus;
    inproc_executor<> ex{bus};
    inproc_socket<> sock{ex};
    std::error_code ec = std::make_error_code(std::errc::io_error);
    sock.send(dest, std::span<const std::byte>{payload}, ec);
    REQUIRE_FALSE(ec);
    REQUIRE(bus.has_pending_packets());
}

TEST_CASE("the throwing send queues the datagram", "[inproc_socket][error_code]")
{
    inproc_bus<> bus;
    inproc_executor<> ex{bus};
    inproc_socket<> sock{ex};
    REQUIRE_NOTHROW(sock.send(dest, std::span<const std::byte>{payload}));
    REQUIRE(bus.has_pending_packets());
}

TEST_CASE("the error_code send on a closed socket reports bad_file_descriptor and queues nothing",
    "[inproc_socket][error_code]")
{
    inproc_bus<> bus;
    inproc_executor<> ex{bus};
    inproc_socket<> sock{ex};
    sock.close();
    std::error_code ec = std::make_error_code(std::errc::io_error);
    sock.send(dest, std::span<const std::byte>{payload}, ec);
    REQUIRE(ec == std::errc::bad_file_descriptor);
    REQUIRE_FALSE(bus.has_pending_packets());
}

TEST_CASE("the throwing send on a closed socket throws bad_file_descriptor", "[inproc_socket][error_code]")
{
    inproc_bus<> bus;
    inproc_executor<> ex{bus};
    inproc_socket<> sock{ex};
    sock.close();
    REQUIRE(send_exception(sock) == std::errc::bad_file_descriptor);
    REQUIRE_FALSE(bus.has_pending_packets());
}
