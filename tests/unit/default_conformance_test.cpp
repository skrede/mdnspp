// tests/native_conformance_test.cpp

#include "mdnspp/default/default_policy.h"
#include "mdnspp/policy.h"
#include "mdnspp/socket_options.h"

static_assert(mdnspp::policy_like<mdnspp::default_policy>, "default_policy must satisfy policy_like");
static_assert(mdnspp::socket_like<mdnspp::default_socket>, "default_socket must satisfy socket_like");
static_assert(mdnspp::timer_like<mdnspp::default_timer>, "default_timer must satisfy timer_like");
static_assert(std::constructible_from<mdnspp::default_socket, mdnspp::default_context&, const mdnspp::socket_options&>,
              "default_socket must be constructible from (context, socket_options)");
static_assert(std::constructible_from<mdnspp::default_socket, mdnspp::default_context&, const mdnspp::socket_options&, std::error_code&>,
              "default_socket must be constructible from (context, socket_options, error_code)");

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
// well-formed (complete types) with default_policy.
// ---------------------------------------------------------------------------
static_assert(sizeof(mdnspp::basic_observer<mdnspp::default_policy>) > 0, "basic_observer<default_policy> must be a complete type");
static_assert(sizeof(mdnspp::basic_service_discovery<mdnspp::default_policy>) > 0, "basic_service_discovery<default_policy> must be a complete type");
static_assert(sizeof(mdnspp::basic_querier<mdnspp::default_policy>) > 0, "basic_querier<default_policy> must be a complete type");
static_assert(sizeof(mdnspp::basic_service_server<mdnspp::default_policy>) > 0, "basic_service_server<default_policy> must be a complete type");

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST_CASE("default_policy satisfies policy_like concept (compile-time)", "[concept][conformance][native]")
{
    // The real test is the static_assert above. This test documents the runtime smoke test.
    SUCCEED("default_policy static_assert passed at compile time");
}

TEST_CASE("default_context run/stop lifecycle", "[native][context]")
{
    mdnspp::default_context ctx;

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
    SUCCEED("default_context run/stop lifecycle works correctly");
}

TEST_CASE("default_timer expires_after drops pending handler", "[native][timer]")
{
    mdnspp::default_context ctx;
    mdnspp::default_timer timer{ctx};

    bool called = false;
    timer.async_wait([&](std::error_code) { called = true; });
    REQUIRE(timer.has_pending());

    // expires_after should silently drop the pending handler without calling it
    timer.expires_after(100ms);
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE_FALSE(called); // handler was dropped, not called
}

TEST_CASE("default_timer cancel delivers operation_canceled", "[native][timer]")
{
    mdnspp::default_context ctx;
    mdnspp::default_timer timer{ctx};

    std::error_code received{};
    timer.async_wait([&](std::error_code ec) { received = ec; });
    REQUIRE(timer.has_pending());

    timer.cancel();
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE(received == std::make_error_code(std::errc::operation_canceled));
}

TEST_CASE("default_timer fires after deadline via run()", "[native][timer]")
{
    mdnspp::default_context ctx;
    mdnspp::default_timer timer{ctx};

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

TEST_CASE("default_context dispatches data on registered loopback socket", "[native][context][socket]")
{
    mdnspp::default_context ctx;

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

    ctx.register_socket(fd, [&](std::error_code, const mdnspp::recv_metadata &meta, std::span<std::byte> data)
    {
        handler_called = true;
        received_data.assign(reinterpret_cast<const char*>(data.data()), data.size());
        received_ep = meta.sender;
    });

    // Send data to ourselves
    const std::string payload = "hello";
#ifdef _WIN32
    REQUIRE(::sendto(fd, payload.data(), static_cast<int>(payload.size()), 0,
                     reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == static_cast<int>(payload.size()));
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

TEST_CASE("default_context deregister_socket stops dispatch", "[native][context][socket]")
{
    mdnspp::default_context ctx;

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
    ctx.register_socket(fd, [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)
    {
        ++call_count;
    });

    // Deregister before sending
    ctx.deregister_socket(fd);

    const std::string payload = "nope";
#ifdef _WIN32
    (void)::sendto(fd, payload.data(), static_cast<int>(payload.size()), 0,
                   reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
#else
    (void)::sendto(fd, payload.data(), payload.size(), 0,
                   reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
#endif

    ctx.poll_one();
    std::this_thread::sleep_for(5ms);
    ctx.poll_one();

    REQUIRE(call_count == 0);

    mdnspp::detail::close_socket(fd);
}

TEST_CASE("default_context poll_one returns immediately with no sockets", "[native][context]")
{
    mdnspp::default_context ctx;

    const auto start = std::chrono::steady_clock::now();
    ctx.poll_one();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    // poll_one with timeout=0 should return nearly instantly
    REQUIRE(elapsed < 50ms);
}

TEST_CASE("default_context restart then run works after stop", "[native][context]")
{
    mdnspp::default_context ctx;

    // First cycle: stop then run returns immediately.
    ctx.stop();
    ctx.run();

    // Restart resets the stopped flag — run() should block until stop().
    ctx.restart();
    std::thread stopper{
        [&ctx]
        {
            std::this_thread::sleep_for(30ms);
            ctx.stop();
        }
    };
    ctx.run();
    stopper.join();

    // Second restart cycle — prove it is reusable more than once.
    ctx.restart();
    std::thread stopper2{
        [&ctx]
        {
            std::this_thread::sleep_for(30ms);
            ctx.stop();
        }
    };
    ctx.run();
    stopper2.join();

    SUCCEED("restart/run/stop works across multiple cycles");
}

TEST_CASE("default_context register_socket twice replaces handler", "[native][context][socket]")
{
    mdnspp::default_context ctx;

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

    int first_count = 0;
    int second_count = 0;

    // Register first handler
    ctx.register_socket(fd, [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>) { ++first_count; });

    // Register second handler for the same fd — must replace, not duplicate.
    ctx.register_socket(fd, [&](std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>) { ++second_count; });

    // Send data to ourselves
    const std::string payload = "test";
#ifdef _WIN32
    (void)::sendto(fd, payload.data(), static_cast<int>(payload.size()), 0,
                   reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
#else
    (void)::sendto(fd, payload.data(), payload.size(), 0,
                   reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
#endif

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

TEST_CASE("default_context deregister_socket for unregistered fd is a no-op", "[native][context]")
{
    mdnspp::default_context ctx;

    // Deregistering a fd that was never registered should not crash or throw.
    REQUIRE_NOTHROW(ctx.deregister_socket(42));
    REQUIRE_NOTHROW(ctx.deregister_socket(mdnspp::detail::invalid_socket));
}

TEST_CASE("default_socket with default socket_options", "[native][socket][socket_options]")
{
    mdnspp::default_context ctx;
    try
    {
        mdnspp::socket_options opts{};
        mdnspp::default_socket sock{ctx, opts};
        SUCCEED("default_socket constructed with default socket_options (INADDR_ANY, TTL=255)");
    }
    catch(const std::exception &e)
    {
        WARN("default_socket construction with socket_options failed (expected in no-network CI): " << e.what());
    }
}

TEST_CASE("default_socket with socket_options and error_code", "[native][socket][socket_options]")
{
    mdnspp::default_context ctx;
    mdnspp::socket_options opts{};
    std::error_code ec;
    mdnspp::default_socket sock{ctx, opts, ec};
    if(ec)
        WARN("default_socket non-throwing construction with socket_options failed (expected in no-network CI): " << ec.message());
    else
        SUCCEED("default_socket constructed with default socket_options via error_code overload");
}

TEST_CASE("default_context stop from another thread wakes run", "[native][context]")
{
    mdnspp::default_context ctx;

    std::atomic<bool> run_returned{false};

    std::thread runner{
        [&]
        {
            ctx.run();
            run_returned.store(true, std::memory_order_release);
        }
    };

    // Give run() a moment to enter the poll loop.
    std::this_thread::sleep_for(30ms);
    REQUIRE_FALSE(run_returned.load(std::memory_order_acquire));

    ctx.stop();
    runner.join();

    REQUIRE(run_returned.load(std::memory_order_acquire));
}

TEST_CASE("default_socket construction joins multicast group", "[native][socket]")
{
    mdnspp::default_context ctx;
    // May fail in sandboxed CI with no multicast-capable interface.
    try
    {
        mdnspp::default_socket sock{ctx};
        SUCCEED("default_socket constructed and multicast group 224.0.0.251:5353 joined");
    }
    catch(const std::exception &e)
    {
        WARN("default_socket construction failed (expected in no-network CI): " << e.what());
    }
}

TEST_CASE("All four public types instantiate with default_policy", "[native][policy][instantiation]")
{
    mdnspp::default_context ctx;

    try
    {
        mdnspp::basic_observer<mdnspp::default_policy> obs{
            ctx,
            mdnspp::observer_options{.on_record = [](const mdnspp::endpoint &, const mdnspp::mdns_record_variant &)
            {
            }}
        };
        SUCCEED("observer<default_policy> constructed");
    }
    catch(const std::exception &e)
    {
        WARN("observer<default_policy> construction failed (no-network CI): " << e.what());
    }

    try
    {
        mdnspp::basic_service_discovery<mdnspp::default_policy> sd{ctx};
        SUCCEED("service_discovery<default_policy> constructed");
    }
    catch(const std::exception &e)
    {
        WARN("service_discovery<default_policy> construction failed (no-network CI): " << e.what());
    }

    try
    {
        mdnspp::basic_querier<mdnspp::default_policy> q{ctx};
        SUCCEED("querier<default_policy> constructed");
    }
    catch(const std::exception &e)
    {
        WARN("querier<default_policy> construction failed (no-network CI): " << e.what());
    }

    try
    {
        mdnspp::service_info info;
        info.service_name = "TestService._http._tcp.local.";
        info.service_type = "_http._tcp.local.";
        info.hostname = "testhost.local.";
        info.port = 8080;

        mdnspp::basic_service_server<mdnspp::default_policy> srv{ctx, info};
        SUCCEED("service_server<default_policy> constructed");
    }
    catch(const std::exception &e)
    {
        WARN("service_server<default_policy> construction failed (no-network CI): " << e.what());
    }
}
