// tests/native_conformance_test.cpp

#include "mdnspp/default/default_policy.h"
#include "mdnspp/policy.h"

static_assert(mdnspp::Policy<mdnspp::DefaultPolicy>, "DefaultPolicy must satisfy Policy");
static_assert(mdnspp::SocketLike<mdnspp::DefaultSocket>, "DefaultSocket must satisfy SocketLike");
static_assert(mdnspp::TimerLike<mdnspp::DefaultTimer>, "DefaultTimer must satisfy TimerLike");

#include "mdnspp/querier.h"
#include "mdnspp/observer.h"
#include "mdnspp/service_info.h"
#include "mdnspp/service_server.h"
#include "mdnspp/service_discovery.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <thread>

using namespace std::chrono_literals;

// ---------------------------------------------------------------------------
// Compile-time instantiation checks — all four public types must be
// well-formed (complete types) with DefaultPolicy.
// ---------------------------------------------------------------------------
static_assert(sizeof(mdnspp::observer<mdnspp::DefaultPolicy>) > 0, "observer<DefaultPolicy> must be a complete type");
static_assert(sizeof(mdnspp::service_discovery<mdnspp::DefaultPolicy>) > 0, "service_discovery<DefaultPolicy> must be a complete type");
static_assert(sizeof(mdnspp::querier<mdnspp::DefaultPolicy>) > 0, "querier<DefaultPolicy> must be a complete type");
static_assert(sizeof(mdnspp::service_server<mdnspp::DefaultPolicy>) > 0, "service_server<DefaultPolicy> must be a complete type");

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
        mdnspp::observer<mdnspp::DefaultPolicy> obs{
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
        mdnspp::service_discovery<mdnspp::DefaultPolicy> sd{ctx, 500ms};
        SUCCEED("service_discovery<DefaultPolicy> constructed");
    }
    catch(const std::exception &e)
    {
        WARN("service_discovery<DefaultPolicy> construction failed (no-network CI): " << e.what());
    }

    try
    {
        mdnspp::querier<mdnspp::DefaultPolicy> q{ctx, 500ms};
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

        mdnspp::service_server<mdnspp::DefaultPolicy> srv{ctx, info};
        SUCCEED("service_server<DefaultPolicy> constructed");
    }
    catch(const std::exception &e)
    {
        WARN("service_server<DefaultPolicy> construction failed (no-network CI): " << e.what());
    }
}
