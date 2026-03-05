// tests/concept_conformance_test.cpp
// Policy concept conformance tests — Phase 7, Plan 07-03
// Verifies MockPolicy (and its components) satisfy Policy, SocketLike, and TimerLike.
// This TU does NOT link against ASIO.

#include "mdnspp/policy.h"
#include "mdnspp/testing/mock_policy.h"
#include "mdnspp/observer.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"

// If this static_assert fails, MockPolicy does not satisfy Policy.
// Check: executor_type, socket_type, timer_type, constructor signatures.
static_assert(
    mdnspp::Policy<mdnspp::testing::MockPolicy>,
    "MockPolicy must satisfy Policy — check executor_type, socket_type, timer_type"
);

// Individual sub-concept checks for fine-grained diagnostics.
static_assert(
    mdnspp::SocketLike<mdnspp::testing::MockSocket>,
    "MockSocket must satisfy SocketLike — check async_receive/send/close signatures"
);
static_assert(
    mdnspp::TimerLike<mdnspp::testing::MockTimer>,
    "MockTimer must satisfy TimerLike — check expires_after/async_wait/cancel signatures"
);

#include <catch2/catch_test_macros.hpp>

using namespace mdnspp::testing;

TEST_CASE("MockSocket satisfies SocketLike concept", "[concept][conformance]")
{
    MockSocket mock{mock_executor{}};
    REQUIRE(mock.queue_empty());
    REQUIRE(mock.sent_packets().empty());
}

TEST_CASE("MockTimer satisfies TimerLike concept", "[concept][conformance]")
{
    MockTimer timer{mock_executor{}};
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE(timer.cancel_count() == 0);
}

TEST_CASE("MockTimer fire delivers success error_code", "[concept][conformance]")
{
    MockTimer timer{mock_executor{}};
    std::error_code received{std::make_error_code(std::errc::interrupted)};
    timer.async_wait([&](std::error_code ec) { received = ec; });
    REQUIRE(timer.has_pending());
    timer.fire();
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE_FALSE(received);  // success error_code is falsy
}

TEST_CASE("MockTimer cancel delivers operation_canceled", "[concept][conformance]")
{
    MockTimer timer{mock_executor{}};
    std::error_code received{};
    timer.async_wait([&](std::error_code ec) { received = ec; });
    timer.cancel();
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE(received == std::make_error_code(std::errc::operation_canceled));
    REQUIRE(timer.cancel_count() == 1);
}

TEST_CASE("MockTimer expires_after clears pending handler", "[concept][conformance]")
{
    MockTimer timer{mock_executor{}};
    bool called = false;
    timer.async_wait([&](std::error_code) { called = true; });
    REQUIRE(timer.has_pending());
    timer.expires_after(std::chrono::milliseconds{100});
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE_FALSE(called);  // handler was dropped, not called
    REQUIRE(timer.cancel_count() == 1);
}

TEST_CASE("MockSocket error_code constructor path", "[concept][error_code]")
{
    MockSocket::set_fail_on_construct(true);
    std::error_code ec;
    MockSocket sock{mock_executor{}, ec};
    REQUIRE(ec);
    MockSocket::set_fail_on_construct(false); // reset
}

TEST_CASE("observer error_code constructor path", "[observer][error_code]")
{
    MockSocket::set_fail_on_construct(true);
    std::error_code ec;
    mdnspp::observer<mdnspp::testing::MockPolicy> obs{
        mock_executor{},
        [](const mdnspp::mdns_record_variant &, mdnspp::endpoint) {},
        ec};
    REQUIRE(ec);
    MockSocket::set_fail_on_construct(false);
}
