// tests/asio_conformance_test.cpp

#include "mdnspp/asio/asio_policy.h"
#include "mdnspp/policy.h"

static_assert(mdnspp::Policy<mdnspp::AsioPolicy>, "AsioPolicy must satisfy Policy — check AsioSocket/AsioTimer constructor signatures");
static_assert(mdnspp::SocketLike<mdnspp::AsioSocket>, "AsioSocket must satisfy SocketLike — check async_receive/send/close signatures");
static_assert(mdnspp::TimerLike<mdnspp::AsioTimer>, "AsioTimer must satisfy TimerLike — check expires_after/async_wait/cancel signatures");

#include <catch2/catch_test_macros.hpp>

TEST_CASE("AsioPolicy satisfies Policy concept (compile-time)", "[concept][conformance][asio]")
{
    // The real test is the static_assert above. This test documents the runtime smoke test.
    SUCCEED("AsioPolicy static_assert passed at compile time");
}

TEST_CASE("AsioSocket satisfies SocketLike concept", "[concept][conformance][asio]")
{
    asio::io_context io;
    // Construction joins multicast group — may fail in sandboxed CI with no network interface.
    try
    {
        mdnspp::AsioSocket socket{io};
        SUCCEED("AsioSocket constructed and multicast group joined");
    }
    catch(const std::exception &e)
    {
        WARN("AsioSocket construction failed (expected in no-network CI): " << e.what());
    }
}

TEST_CASE("AsioTimer satisfies TimerLike concept", "[concept][conformance][asio]")
{
    asio::io_context io;
    mdnspp::AsioTimer timer{io};
    // Verify the methods are callable (concept already verified at compile time)
    timer.expires_after(std::chrono::milliseconds{100});
    timer.cancel();
    SUCCEED("AsioTimer methods callable");
}
