// tests/native_conformance_test.cpp

#include "mdnspp/default/default_policy.h"
#include "mdnspp/policy.h"

static_assert(mdnspp::Policy<mdnspp::DefaultPolicy>, "DefaultPolicy must satisfy Policy");
static_assert(mdnspp::SocketLike<mdnspp::DefaultSocket>, "DefaultSocket must satisfy SocketLike");
static_assert(mdnspp::TimerLike<mdnspp::DefaultTimer>, "DefaultTimer must satisfy TimerLike");

#include "mdnspp/basic_querier.h"
#include "mdnspp/basic_observer.h"
#include "mdnspp/service_info.h"
#include "mdnspp/basic_service_server.h"
#include "mdnspp/basic_service_discovery.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <span>
#include <string>
#include <thread>

#ifndef _WIN32
#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

using namespace std::chrono_literals;

// ---------------------------------------------------------------------------
// Compile-time instantiation checks — all four public types must be
// well-formed (complete types) with DefaultPolicy.
// ---------------------------------------------------------------------------
static_assert(sizeof(mdnspp::basic_observer<mdnspp::DefaultPolicy>) > 0, "basic_observer<DefaultPolicy> must be a complete type");
static_assert(sizeof(mdnspp::basic_service_discovery<mdnspp::DefaultPolicy>) > 0, "basic_service_discovery<DefaultPolicy> must be a complete type");
static_assert(sizeof(mdnspp::basic_querier<mdnspp::DefaultPolicy>) > 0, "basic_querier<DefaultPolicy> must be a complete type");
static_assert(sizeof(mdnspp::basic_service_server<mdnspp::DefaultPolicy>) > 0, "basic_service_server<DefaultPolicy> must be a complete type");

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST_CASE("DefaultPolicy satisfies Policy concept (compile-time)", "[concept][conformance][native]")
{
    // The real test is the static_assert above. This test documents the runtime smoke test.
    SUCCEED("DefaultPolicy static_assert passed at compile time");
}

TEST_CASE("DefaultContext run/stop lifecycle", "[native][context]")
{
    mdnspp::DefaultContext ctx;

    // stop() before run() — run() must return immediately
    ctx.stop();
    ctx.run(); // should return without blocking

    // restart() + stop() from another thread — run() must return
    ctx.restart();
    std::thread stopper{
        [&ctx]
        {
            std::this_thread::sleep_for(50ms);
            ctx.stop();
        }
    };
    ctx.run(); // blocks until stopper fires stop()
    stopper.join();
    SUCCEED("DefaultContext run/stop lifecycle works correctly");
}

TEST_CASE("DefaultTimer expires_after drops pending handler", "[native][timer]")
{
    mdnspp::DefaultContext ctx;
    mdnspp::DefaultTimer timer{ctx};

    bool called = false;
    timer.async_wait([&](std::error_code) { called = true; });
    REQUIRE(timer.has_pending());

    // expires_after should silently drop the pending handler without calling it
    timer.expires_after(100ms);
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE_FALSE(called); // handler was dropped, not called
}

TEST_CASE("DefaultTimer cancel delivers operation_canceled", "[native][timer]")
{
    mdnspp::DefaultContext ctx;
    mdnspp::DefaultTimer timer{ctx};

    std::error_code received{};
    timer.async_wait([&](std::error_code ec) { received = ec; });
    REQUIRE(timer.has_pending());

    timer.cancel();
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE(received == std::make_error_code(std::errc::operation_canceled));
}

TEST_CASE("DefaultTimer fires after deadline via run()", "[native][timer]")
{
    mdnspp::DefaultContext ctx;
    mdnspp::DefaultTimer timer{ctx};

    bool fired = false;
    std::error_code ec_received{std::make_error_code(std::errc::interrupted)};

    timer.expires_after(10ms);
    timer.async_wait([&](std::error_code ec)
    {
        fired = true;
        ec_received = ec;
    });

    // Poll in a loop on the calling thread until the handler fires.
    while(!fired)
    {
        ctx.poll_one();
        std::this_thread::sleep_for(1ms);
    }

    REQUIRE(fired);
    REQUIRE_FALSE(ec_received); // success error_code is falsy
}

TEST_CASE("DefaultContext dispatches data on registered loopback socket", "[native][context][socket]")
{
    mdnspp::DefaultContext ctx;

    // Create a plain UDP socket on loopback
    auto fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(fd != mdnspp::detail::invalid_socket);

    // Bind to loopback on an ephemeral port
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0; // OS picks a port
    REQUIRE(::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);

    // Query the assigned port
#ifdef _WIN32
    int len = sizeof(addr);
#else
    socklen_t len = sizeof(addr);
#endif
    REQUIRE(::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len) == 0);

    // Make non-blocking
#ifdef _WIN32
    {
        u_long mode = 1;
        REQUIRE(::ioctlsocket(fd, FIONBIO, &mode) == 0);
    }
#else
    {
        int flags = ::fcntl(fd, F_GETFL, 0);
        REQUIRE(flags >= 0);
        REQUIRE(::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
    }
#endif

    // Register with context
    bool handler_called = false;
    std::string received_data;
    mdnspp::endpoint received_ep;

    ctx.register_socket(fd, [&](std::span<std::byte> data, mdnspp::endpoint ep)
    {
        handler_called = true;
        received_data.assign(reinterpret_cast<const char *>(data.data()), data.size());
        received_ep = ep;
    });

    // Send data to ourselves
    const std::string payload = "hello";
#ifdef _WIN32
    REQUIRE(::sendto(fd, payload.data(), static_cast<int>(payload.size()), 0,
                     reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == static_cast<int>(payload.size()));
#else
    REQUIRE(::sendto(fd, payload.data(), payload.size(), 0,
                     reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == static_cast<ssize_t>(payload.size()));
#endif

    // Poll until handler fires (bounded attempts)
    for(int attempt = 0; attempt < 50 && !handler_called; ++attempt)
    {
        ctx.poll_one();
        std::this_thread::sleep_for(1ms);
    }

    REQUIRE(handler_called);
    REQUIRE(received_data == "hello");
    REQUIRE(received_ep.address == "127.0.0.1");
    REQUIRE(received_ep.port != 0);

    // Deregister and cleanup
    ctx.deregister_socket(fd);
    mdnspp::detail::close_socket(fd);
}

TEST_CASE("DefaultContext deregister_socket stops dispatch", "[native][context][socket]")
{
    mdnspp::DefaultContext ctx;

    auto fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(fd != mdnspp::detail::invalid_socket);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    REQUIRE(::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);

#ifdef _WIN32
    int len = sizeof(addr);
#else
    socklen_t len = sizeof(addr);
#endif
    REQUIRE(::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len) == 0);

#ifdef _WIN32
    {
        u_long mode = 1;
        REQUIRE(::ioctlsocket(fd, FIONBIO, &mode) == 0);
    }
#else
    {
        int flags = ::fcntl(fd, F_GETFL, 0);
        REQUIRE(::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
    }
#endif

    int call_count = 0;
    ctx.register_socket(fd, [&](std::span<std::byte>, mdnspp::endpoint)
    {
        ++call_count;
    });

    // Deregister before sending
    ctx.deregister_socket(fd);

    const std::string payload = "nope";
#ifdef _WIN32
    (void)::sendto(fd, payload.data(), static_cast<int>(payload.size()), 0,
                   reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
#else
    (void)::sendto(fd, payload.data(), payload.size(), 0,
                   reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
#endif

    ctx.poll_one();
    std::this_thread::sleep_for(5ms);
    ctx.poll_one();

    REQUIRE(call_count == 0);

    mdnspp::detail::close_socket(fd);
}

TEST_CASE("DefaultContext poll_one returns immediately with no sockets", "[native][context]")
{
    mdnspp::DefaultContext ctx;

    const auto start = std::chrono::steady_clock::now();
    ctx.poll_one();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    // poll_one with timeout=0 should return nearly instantly
    REQUIRE(elapsed < 50ms);
}

TEST_CASE("DefaultContext restart then run works after stop", "[native][context]")
{
    mdnspp::DefaultContext ctx;

    // First cycle: stop then run returns immediately.
    ctx.stop();
    ctx.run();

    // Restart resets the stopped flag — run() should block until stop().
    ctx.restart();
    std::thread stopper{[&ctx]
    {
        std::this_thread::sleep_for(30ms);
        ctx.stop();
    }};
    ctx.run();
    stopper.join();

    // Second restart cycle — prove it is reusable more than once.
    ctx.restart();
    std::thread stopper2{[&ctx]
    {
        std::this_thread::sleep_for(30ms);
        ctx.stop();
    }};
    ctx.run();
    stopper2.join();

    SUCCEED("restart/run/stop works across multiple cycles");
}

TEST_CASE("DefaultContext register_socket twice replaces handler", "[native][context][socket]")
{
    mdnspp::DefaultContext ctx;

    auto fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(fd != mdnspp::detail::invalid_socket);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    REQUIRE(::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);

    socklen_t len = sizeof(addr);
    REQUIRE(::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len) == 0);

    // Make non-blocking
    {
        int flags = ::fcntl(fd, F_GETFL, 0);
        REQUIRE(flags >= 0);
        REQUIRE(::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
    }

    int first_count = 0;
    int second_count = 0;

    // Register first handler
    ctx.register_socket(fd, [&](std::span<std::byte>, mdnspp::endpoint) { ++first_count; });

    // Register second handler for the same fd — must replace, not duplicate.
    ctx.register_socket(fd, [&](std::span<std::byte>, mdnspp::endpoint) { ++second_count; });

    // Send data to ourselves
    const std::string payload = "test";
    (void)::sendto(fd, payload.data(), payload.size(), 0,
                   reinterpret_cast<sockaddr *>(&addr), sizeof(addr));

    for(int attempt = 0; attempt < 50 && second_count == 0; ++attempt)
    {
        ctx.poll_one();
        std::this_thread::sleep_for(1ms);
    }

    REQUIRE(first_count == 0);  // first handler was replaced
    REQUIRE(second_count == 1); // only second handler fires

    ctx.deregister_socket(fd);
    mdnspp::detail::close_socket(fd);
}

TEST_CASE("DefaultContext deregister_socket for unregistered fd is a no-op", "[native][context]")
{
    mdnspp::DefaultContext ctx;

    // Deregistering a fd that was never registered should not crash or throw.
    REQUIRE_NOTHROW(ctx.deregister_socket(42));
    REQUIRE_NOTHROW(ctx.deregister_socket(mdnspp::detail::invalid_socket));
}

TEST_CASE("DefaultContext stop from another thread wakes run", "[native][context]")
{
    mdnspp::DefaultContext ctx;

    std::atomic<bool> run_returned{false};

    std::thread runner{[&]
    {
        ctx.run();
        run_returned.store(true, std::memory_order_release);
    }};

    // Give run() a moment to enter the poll loop.
    std::this_thread::sleep_for(30ms);
    REQUIRE_FALSE(run_returned.load(std::memory_order_acquire));

    ctx.stop();
    runner.join();

    REQUIRE(run_returned.load(std::memory_order_acquire));
}

TEST_CASE("DefaultSocket construction joins multicast group", "[native][socket]")
{
    mdnspp::DefaultContext ctx;
    // May fail in sandboxed CI with no multicast-capable interface.
    try
    {
        mdnspp::DefaultSocket sock{ctx};
        SUCCEED("DefaultSocket constructed and multicast group 224.0.0.251:5353 joined");
    }
    catch(const std::exception &e)
    {
        WARN("DefaultSocket construction failed (expected in no-network CI): " << e.what());
    }
}

TEST_CASE("All four public types instantiate with DefaultPolicy", "[native][policy][instantiation]")
{
    mdnspp::DefaultContext ctx;

    try
    {
        mdnspp::basic_observer<mdnspp::DefaultPolicy> obs{
            ctx,
            [](const mdnspp::mdns_record_variant &, mdnspp::endpoint)
            {
            }
        };
        SUCCEED("observer<DefaultPolicy> constructed");
    }
    catch(const std::exception &e)
    {
        WARN("observer<DefaultPolicy> construction failed (no-network CI): " << e.what());
    }

    try
    {
        mdnspp::basic_service_discovery<mdnspp::DefaultPolicy> sd{ctx, 500ms};
        SUCCEED("service_discovery<DefaultPolicy> constructed");
    }
    catch(const std::exception &e)
    {
        WARN("service_discovery<DefaultPolicy> construction failed (no-network CI): " << e.what());
    }

    try
    {
        mdnspp::basic_querier<mdnspp::DefaultPolicy> q{ctx, 500ms};
        SUCCEED("querier<DefaultPolicy> constructed");
    }
    catch(const std::exception &e)
    {
        WARN("querier<DefaultPolicy> construction failed (no-network CI): " << e.what());
    }

    try
    {
        mdnspp::service_info info;
        info.service_name = "TestService._http._tcp.local.";
        info.service_type = "_http._tcp.local.";
        info.hostname = "testhost.local.";
        info.port = 8080;

        mdnspp::basic_service_server<mdnspp::DefaultPolicy> srv{ctx, info};
        SUCCEED("service_server<DefaultPolicy> constructed");
    }
    catch(const std::exception &e)
    {
        WARN("service_server<DefaultPolicy> construction failed (no-network CI): " << e.what());
    }
}
