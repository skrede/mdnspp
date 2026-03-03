// tests/asio_conformance_test.cpp
// TEST-04: SocketPolicy and TimerPolicy concept conformance — Phase 2 (AsioSocketPolicy, AsioTimerPolicy)
// Compiled only when MDNSPP_ENABLE_ASIO_POLICY=ON.
// This TU links against ASIO (via mdnspp_asio target).

#include "mdnspp/asio/asio_socket_policy.h"
#include "mdnspp/asio/asio_timer_policy.h"
#include "mdnspp/socket_policy.h"
#include "mdnspp/timer_policy.h"

// If these static_asserts fail, check method signatures against the concept requirements.
static_assert(
    mdnspp::SocketPolicy<mdnspp::asio_policy::AsioSocketPolicy>,
    "AsioSocketPolicy must satisfy SocketPolicy — check async_receive/send/close signatures"
);
static_assert(
    mdnspp::TimerPolicy<mdnspp::asio_policy::AsioTimerPolicy>,
    "AsioTimerPolicy must satisfy TimerPolicy — check expires_after/async_wait/cancel signatures"
);

#include <catch2/catch_test_macros.hpp>

TEST_CASE("AsioSocketPolicy satisfies SocketPolicy concept", "[concept][conformance][asio]")
{
    asio::io_context io;
    // Construction joins multicast group — may fail in sandboxed CI with no network interface.
    // The static_assert above is the real TEST-04 gate; this is a runtime smoke test.
    try
    {
        mdnspp::asio_policy::AsioSocketPolicy policy{io};
        SUCCEED("AsioSocketPolicy constructed and multicast group joined");
    }
    catch(const std::exception &e)
    {
        WARN("AsioSocketPolicy construction failed (expected in no-network CI): " << e.what());
    }
}

TEST_CASE("AsioTimerPolicy satisfies TimerPolicy concept", "[concept][conformance][asio]")
{
    asio::io_context io;
    mdnspp::asio_policy::AsioTimerPolicy policy{io};
    // Verify the methods are callable (concept already verified at compile time)
    policy.expires_after(std::chrono::milliseconds{100});
    policy.cancel();
    SUCCEED("AsioTimerPolicy methods callable");
}
