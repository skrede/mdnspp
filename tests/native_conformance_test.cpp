// tests/native_conformance_test.cpp
// Policy concept conformance — NativePolicy (Phase 9, Plan 09-02)
// Compiled only when MDNSPP_ENABLE_NATIVE_POLICY=ON.
// This TU links against mdnspp_native — NO ASIO.

#include "mdnspp/native/native_policy.h"
#include "mdnspp/policy.h"

// ---------------------------------------------------------------------------
// Compile-time concept checks
// ---------------------------------------------------------------------------
static_assert(mdnspp::Policy<mdnspp::NativePolicy>,
              "NativePolicy must satisfy Policy");
static_assert(mdnspp::SocketLike<mdnspp::NativeSocket>,
              "NativeSocket must satisfy SocketLike");
static_assert(mdnspp::TimerLike<mdnspp::NativeTimer>,
              "NativeTimer must satisfy TimerLike");

#include <catch2/catch_test_macros.hpp>

#include "mdnspp/observer.h"
#include "mdnspp/service_discovery.h"
#include "mdnspp/querent.h"
#include "mdnspp/service_server.h"
#include "mdnspp/service_info.h"

#include <chrono>
#include <thread>

using namespace std::chrono_literals;

// ---------------------------------------------------------------------------
// Compile-time instantiation checks — all four public types must be
// well-formed (complete types) with NativePolicy.
// ---------------------------------------------------------------------------
static_assert(sizeof(mdnspp::observer<mdnspp::NativePolicy>) > 0,
              "observer<NativePolicy> must be a complete type");
static_assert(sizeof(mdnspp::service_discovery<mdnspp::NativePolicy>) > 0,
              "service_discovery<NativePolicy> must be a complete type");
static_assert(sizeof(mdnspp::querent<mdnspp::NativePolicy>) > 0,
              "querent<NativePolicy> must be a complete type");
static_assert(sizeof(mdnspp::service_server<mdnspp::NativePolicy>) > 0,
              "service_server<NativePolicy> must be a complete type");

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

TEST_CASE("NativePolicy satisfies Policy concept (compile-time)", "[concept][conformance][native]")
{
    // The real test is the static_assert above. This test documents the runtime smoke test.
    SUCCEED("NativePolicy static_assert passed at compile time");
}

TEST_CASE("NativeContext run/stop lifecycle", "[native][context]")
{
    mdnspp::NativeContext ctx;

    // stop() before run() — run() must return immediately
    ctx.stop();
    ctx.run(); // should return without blocking

    // restart() + stop() from another thread — run() must return
    ctx.restart();
    std::thread stopper{[&ctx]
    {
        std::this_thread::sleep_for(50ms);
        ctx.stop();
    }};
    ctx.run(); // blocks until stopper fires stop()
    stopper.join();
    SUCCEED("NativeContext run/stop lifecycle works correctly");
}

TEST_CASE("NativeTimer expires_after drops pending handler", "[native][timer]")
{
    mdnspp::NativeContext ctx;
    mdnspp::NativeTimer timer{ctx};

    bool called = false;
    timer.async_wait([&](std::error_code) { called = true; });
    REQUIRE(timer.has_pending());

    // expires_after should silently drop the pending handler without calling it
    timer.expires_after(100ms);
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE_FALSE(called); // handler was dropped, not called
}

TEST_CASE("NativeTimer cancel delivers operation_canceled", "[native][timer]")
{
    mdnspp::NativeContext ctx;
    mdnspp::NativeTimer timer{ctx};

    std::error_code received{};
    timer.async_wait([&](std::error_code ec) { received = ec; });
    REQUIRE(timer.has_pending());

    timer.cancel();
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE(received == std::make_error_code(std::errc::operation_canceled));
}

TEST_CASE("NativeTimer fires after deadline via run()", "[native][timer]")
{
    mdnspp::NativeContext ctx;
    mdnspp::NativeTimer timer{ctx};

    bool fired         = false;
    std::error_code ec_received{std::make_error_code(std::errc::interrupted)};

    timer.expires_after(10ms);
    timer.async_wait([&](std::error_code ec)
    {
        fired       = true;
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

TEST_CASE("NativeSocket construction joins multicast group", "[native][socket]")
{
    mdnspp::NativeContext ctx;
    // May fail in sandboxed CI with no multicast-capable interface.
    try
    {
        mdnspp::NativeSocket sock{ctx};
        SUCCEED("NativeSocket constructed and multicast group 224.0.0.251:5353 joined");
    }
    catch(const std::exception& e)
    {
        WARN("NativeSocket construction failed (expected in no-network CI): " << e.what());
    }
}

TEST_CASE("All four public types instantiate with NativePolicy", "[native][policy][instantiation]")
{
    mdnspp::NativeContext ctx;

    // observer<NativePolicy>
    try
    {
        mdnspp::observer<mdnspp::NativePolicy> obs{
            ctx,
            [](mdnspp::mdns_record_variant, mdnspp::endpoint) {}};
        SUCCEED("observer<NativePolicy> constructed");
    }
    catch(const std::exception& e)
    {
        WARN("observer<NativePolicy> construction failed (no-network CI): " << e.what());
    }

    // service_discovery<NativePolicy>
    try
    {
        mdnspp::service_discovery<mdnspp::NativePolicy> sd{ctx, 500ms};
        SUCCEED("service_discovery<NativePolicy> constructed");
    }
    catch(const std::exception& e)
    {
        WARN("service_discovery<NativePolicy> construction failed (no-network CI): " << e.what());
    }

    // querent<NativePolicy>
    try
    {
        mdnspp::querent<mdnspp::NativePolicy> q{ctx, 500ms};
        SUCCEED("querent<NativePolicy> constructed");
    }
    catch(const std::exception& e)
    {
        WARN("querent<NativePolicy> construction failed (no-network CI): " << e.what());
    }

    // service_server<NativePolicy>
    try
    {
        mdnspp::service_info info;
        info.service_name = "TestService._http._tcp.local.";
        info.service_type = "_http._tcp.local.";
        info.hostname     = "testhost.local.";
        info.port         = 8080;

        mdnspp::service_server<mdnspp::NativePolicy> srv{ctx, info};
        SUCCEED("service_server<NativePolicy> constructed");
    }
    catch(const std::exception& e)
    {
        WARN("service_server<NativePolicy> construction failed (no-network CI): " << e.what());
    }
}
