// tests/asio_conformance_test.cpp
// ASIO policy concept conformance tests — compiled only when MDNSPP_ENABLE_ASIO_POLICY=ON
// Verifies that AsioSocketPolicy satisfies SocketPolicy and AsioTimerPolicy satisfies TimerPolicy.
// The real verification is the static_assert in each header; this test provides Catch2 linkage.

#include "mdnspp/asio/asio_socket_policy.h"
#include "mdnspp/asio/asio_timer_policy.h"

// static_assert(SocketPolicy<AsioSocketPolicy>) fires at include time (in asio_socket_policy.h)
// static_assert(TimerPolicy<AsioTimerPolicy>) fires at include time (in asio_timer_policy.h)

#include <catch2/catch_test_macros.hpp>

TEST_CASE("AsioSocketPolicy satisfies SocketPolicy concept", "[concept][conformance][asio]")
{
    // Compile-time check is in the header static_assert.
    // Runtime: verify the static_assert constant evaluates true via type_traits.
    REQUIRE(mdnspp::SocketPolicy<mdnspp::asio_policy::AsioSocketPolicy>);
}

TEST_CASE("AsioTimerPolicy satisfies TimerPolicy concept", "[concept][conformance][asio]")
{
    // Compile-time check is in the header static_assert.
    // Runtime: verify the static_assert constant evaluates true via type_traits.
    REQUIRE(mdnspp::TimerPolicy<mdnspp::asio_policy::AsioTimerPolicy>);
}
