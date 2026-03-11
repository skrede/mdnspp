// tests/concept_conformance_test.cpp

#include "mdnspp/policy.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/testing/mock_policy.h"
#include "mdnspp/basic_observer.h"
#include "mdnspp/observer_options.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"

static_assert(mdnspp::Policy<mdnspp::testing::MockPolicy>, "MockPolicy must satisfy Policy — check executor_type, socket_type, timer_type");
static_assert(mdnspp::SocketLike<mdnspp::testing::MockSocket>, "MockSocket must satisfy SocketLike — check async_receive/send/close signatures");
static_assert(mdnspp::TimerLike<mdnspp::testing::MockTimer>, "MockTimer must satisfy TimerLike — check expires_after/async_wait/cancel signatures");
static_assert(std::constructible_from<mdnspp::testing::MockSocket, mdnspp::testing::mock_executor&, const mdnspp::socket_options&>,
              "MockSocket must be constructible from (executor, socket_options)");
static_assert(std::constructible_from<mdnspp::testing::MockSocket, mdnspp::testing::mock_executor&, const mdnspp::socket_options&, std::error_code&>,
              "MockSocket must be constructible from (executor, socket_options, error_code)");

#include <catch2/catch_test_macros.hpp>

using namespace mdnspp::testing;

TEST_CASE("MockSocket satisfies SocketLike concept", "[concept][conformance]")
{
    mock_executor ex;
    MockSocket mock{ex};
    REQUIRE(mock.queue_empty());
    REQUIRE(mock.sent_packets().empty());
}

TEST_CASE("MockTimer satisfies TimerLike concept", "[concept][conformance]")
{
    mock_executor ex;
    MockTimer timer{ex};
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE(timer.cancel_count() == 0);
}

TEST_CASE("MockTimer fire delivers success error_code", "[concept][conformance]")
{
    mock_executor ex;
    MockTimer timer{ex};
    std::error_code received{std::make_error_code(std::errc::interrupted)};
    timer.async_wait([&](std::error_code ec) { received = ec; });
    REQUIRE(timer.has_pending());
    timer.fire();
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE_FALSE(received); // success error_code is falsy
}

TEST_CASE("MockTimer cancel delivers operation_canceled", "[concept][conformance]")
{
    mock_executor ex;
    MockTimer timer{ex};
    std::error_code received{};
    timer.async_wait([&](std::error_code ec) { received = ec; });
    timer.cancel();
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE(received == std::make_error_code(std::errc::operation_canceled));
    REQUIRE(timer.cancel_count() == 1);
}

TEST_CASE("MockTimer expires_after clears pending handler", "[concept][conformance]")
{
    mock_executor ex;
    MockTimer timer{ex};
    bool called = false;
    timer.async_wait([&](std::error_code) { called = true; });
    REQUIRE(timer.has_pending());
    timer.expires_after(std::chrono::milliseconds{100});
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE_FALSE(called); // handler was dropped, not called
    REQUIRE(timer.cancel_count() == 1);
}

TEST_CASE("MockSocket error_code constructor path", "[concept][error_code]")
{
    MockSocket::set_fail_on_construct(true);
    mock_executor ex;
    std::error_code ec;
    MockSocket sock{ex, ec};
    REQUIRE(ec);
    MockSocket::set_fail_on_construct(false); // reset
}

TEST_CASE("MockPolicy::post pushes to executor queue", "[concept][conformance][post]")
{
    mock_executor ex;
    bool called = false;
    MockPolicy::post(ex, [&] { called = true; });
    REQUIRE(ex.m_posted.size() == 1);
    REQUIRE_FALSE(called);
}

TEST_CASE("mock_executor::drain_posted executes queued work", "[concept][conformance][post]")
{
    mock_executor ex;
    bool called = false;
    MockPolicy::post(ex, [&] { called = true; });
    ex.drain_posted();
    REQUIRE(called);
    REQUIRE(ex.m_posted.empty());
}

TEST_CASE("drain_posted executes in FIFO order", "[concept][conformance][post]")
{
    mock_executor ex;
    std::vector<int> order;
    MockPolicy::post(ex, [&] { order.push_back(1); });
    MockPolicy::post(ex, [&] { order.push_back(2); });
    ex.drain_posted();
    REQUIRE(order == std::vector<int>{1, 2});
}

TEST_CASE("post accepts move-only callable", "[concept][conformance][post]")
{
    mock_executor ex;
    auto ptr = std::make_unique<int>(42);
    int result = 0;
    MockPolicy::post(ex, [p = std::move(ptr), &result] { result = *p; });
    ex.drain_posted();
    REQUIRE(result == 42);
}

TEST_CASE("MockSocket constructible with socket_options", "[concept][conformance]")
{
    mdnspp::testing::mock_executor ex;
    mdnspp::socket_options opts{};

    mdnspp::testing::MockSocket s1{ex, opts};
    REQUIRE(s1.options().interface_address.empty());

    std::error_code ec;
    mdnspp::testing::MockSocket s2{ex, opts, ec};
    REQUIRE_FALSE(ec);
    REQUIRE(s2.options().interface_address.empty());
}

TEST_CASE("MockSocket ec send records packet on success", "[concept][error_code][send]")
{
    mock_executor ex;
    MockSocket sock{ex};
    const std::byte payload[] = {std::byte{0x01}, std::byte{0x02}};
    mdnspp::endpoint dest{"224.0.0.251", 5353};
    std::error_code ec;
    sock.send(dest, std::span<const std::byte>{payload}, ec);
    REQUIRE_FALSE(ec);
    REQUIRE(sock.sent_packets().size() == 1);
    REQUIRE(sock.sent_packets()[0].dest.address == "224.0.0.251");
    REQUIRE(sock.sent_packets()[0].data.size() == 2);
}

TEST_CASE("MockSocket ec send failure injection", "[concept][error_code][send]")
{
    mock_executor ex;
    MockSocket sock{ex};
    const std::byte payload[] = {std::byte{0x01}};
    mdnspp::endpoint dest{"224.0.0.251", 5353};
    std::error_code ec;

    MockSocket::set_fail_on_send(true);
    sock.send(dest, std::span<const std::byte>{payload}, ec);
    REQUIRE(ec == std::make_error_code(std::errc::network_unreachable));
    REQUIRE(sock.sent_packets().empty());

    MockSocket::set_fail_on_send(false);
    sock.send(dest, std::span<const std::byte>{payload}, ec);
    REQUIRE_FALSE(ec);
    REQUIRE(sock.sent_packets().size() == 1);
}

TEST_CASE("observer error_code constructor path", "[observer][error_code]")
{
    MockSocket::set_fail_on_construct(true);
    mock_executor ex;
    std::error_code ec;
    mdnspp::basic_observer<mdnspp::testing::MockPolicy> obs{
        ex,
        mdnspp::observer_options{.on_record = [](const mdnspp::endpoint &, const mdnspp::mdns_record_variant &)
        {
        }},
        {},
        {},
        ec
    };
    REQUIRE(ec);
    MockSocket::set_fail_on_construct(false);
}
