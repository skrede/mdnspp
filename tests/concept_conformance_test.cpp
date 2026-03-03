// tests/concept_conformance_test.cpp
// TEST-04: SocketPolicy concept conformance — Phase 1 (MockSocketPolicy only)
// TEST-03: TimerPolicy concept conformance — Phase 2 (MockTimerPolicy)
// AsioSocketPolicy conformance is Phase 2.
// This TU does NOT link against ASIO.

#include "mdnspp/socket_policy.h"
#include "mdnspp/testing/mock_socket_policy.h"
#include "mdnspp/timer_policy.h"
#include "mdnspp/testing/mock_timer_policy.h"

// If this static_assert fails, MockSocketPolicy does not satisfy SocketPolicy.
// Check: async_receive signature, send signature, close signature.
static_assert(
    mdnspp::SocketPolicy<mdnspp::testing::MockSocketPolicy>,
    "MockSocketPolicy must satisfy SocketPolicy — check method signatures"
);

// If this static_assert fails, MockTimerPolicy does not satisfy TimerPolicy.
// Check: expires_after signature, async_wait signature, cancel signature.
static_assert(
    mdnspp::TimerPolicy<mdnspp::testing::MockTimerPolicy>,
    "MockTimerPolicy must satisfy TimerPolicy — check method signatures"
);

// Minimal Catch2 test to satisfy make_test() linkage requirement.
// The real tests are the static_asserts above (compile-time).
#include <catch2/catch_test_macros.hpp>

TEST_CASE("MockSocketPolicy satisfies SocketPolicy concept", "[concept][conformance]")
{
    // Verify at runtime that MockSocketPolicy is instantiable
    mdnspp::testing::MockSocketPolicy mock;
    REQUIRE(mock.queue_empty());
    REQUIRE(mock.sent_packets().empty());
}

TEST_CASE("MockTimerPolicy satisfies TimerPolicy concept", "[concept][conformance]")
{
    // Verify at runtime that MockTimerPolicy is instantiable and behaves correctly
    mdnspp::testing::MockTimerPolicy timer;
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE(timer.cancel_count() == 0);
}

TEST_CASE("MockTimerPolicy fire delivers success error_code", "[concept][conformance]")
{
    mdnspp::testing::MockTimerPolicy timer;
    std::error_code received{std::make_error_code(std::errc::interrupted)};
    timer.async_wait([&](std::error_code ec) { received = ec; });
    REQUIRE(timer.has_pending());
    timer.fire();
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE_FALSE(received);  // success error_code is falsy
}

TEST_CASE("MockTimerPolicy cancel delivers operation_canceled", "[concept][conformance]")
{
    mdnspp::testing::MockTimerPolicy timer;
    std::error_code received{};
    timer.async_wait([&](std::error_code ec) { received = ec; });
    timer.cancel();
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE(received == std::make_error_code(std::errc::operation_canceled));
    REQUIRE(timer.cancel_count() == 1);
}

TEST_CASE("MockTimerPolicy expires_after clears pending handler", "[concept][conformance]")
{
    mdnspp::testing::MockTimerPolicy timer;
    bool called = false;
    timer.async_wait([&](std::error_code) { called = true; });
    REQUIRE(timer.has_pending());
    timer.expires_after(std::chrono::milliseconds{100});
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE_FALSE(called);  // handler was dropped, not called
    REQUIRE(timer.cancel_count() == 1);
}
