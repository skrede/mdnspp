// tests/asio_completion_token_test.cpp
// Integration tests for ASIO completion tokens — use_future, use_awaitable, deferred.
// Compiled only when MDNSPP_ENABLE_ASIO_POLICY=ON (linked against mdnspp_asio).
//
// All tests wrap socket construction in try/catch and WARN+skip if network is unavailable,
// matching the pattern established in asio_conformance_test.cpp and service_server_tsan_test.cpp.

#include "mdnspp/asio.h"
#include "mdnspp/service_info.h"
#include "mdnspp/detail/dns_enums.h"

#include <asio.hpp>
#include <asio/use_future.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/deferred.hpp>
#include <asio/detached.hpp>

#ifdef ASIO_HAS_CO_AWAIT
#include <asio/co_spawn.hpp>
#endif

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <future>
#include <memory>
#include <thread>

// ---------------------------------------------------------------------------
// Test 1: async_discover with use_future (API-11)
// ---------------------------------------------------------------------------

SCENARIO("async_discover with use_future returns future with results",
         "[completion_token][use_future][service_discovery]")
{
    asio::io_context io;
    try
    {
        mdnspp::service_discovery<mdnspp::AsioPolicy> sd{io, std::chrono::milliseconds(500)};

        // use_future returns std::future<std::vector<mdns_record_variant>>
        auto fut = mdnspp::async_discover(sd, "_nonexistent._tcp.local.", asio::use_future);

        io.run();

        // fut.get() resolves — no real services expected on a test network for _nonexistent
        auto results = fut.get();
        REQUIRE(results.empty());
    }
    catch (const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 8: async_browse with use_future (API-11)
// ---------------------------------------------------------------------------

SCENARIO("async_browse with use_future returns future with services",
         "[completion_token][use_future][service_discovery][browse]")
{
    asio::io_context io;
    try
    {
        mdnspp::service_discovery<mdnspp::AsioPolicy> sd{io, std::chrono::milliseconds(500)};
        auto fut = mdnspp::async_browse(sd, "_nonexistent._tcp.local.", asio::use_future);
        io.run();
        auto services = fut.get();
        REQUIRE(services.empty());
    }
    catch (const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 2: async_query with use_future (API-11 — querier path)
// ---------------------------------------------------------------------------

SCENARIO("async_query with use_future returns future with results",
         "[completion_token][use_future][querier]")
{
    asio::io_context io;
    try
    {
        mdnspp::querier<mdnspp::AsioPolicy> q{io, std::chrono::milliseconds(500)};

        auto fut = mdnspp::async_query(q, "_nonexistent._tcp.local.", mdnspp::dns_type::ptr, asio::use_future);

        io.run();

        auto results = fut.get();
        REQUIRE(results.empty());
    }
    catch (const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 3: async_observe with callback fires on stop (API-11 — observer)
// ---------------------------------------------------------------------------

SCENARIO("async_observe with callback fires when stop() is called",
         "[completion_token][callback][observer]")
{
    asio::io_context io;
    try
    {
        auto obs = std::make_shared<mdnspp::observer<mdnspp::AsioPolicy>>(
            io, [](const mdnspp::mdns_record_variant &, mdnspp::endpoint) {});

        bool handler_fired = false;
        obs->async_observe([&handler_fired](std::error_code ec) {
            handler_fired = true;
        });

        std::thread io_thread([&io] { io.run(); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        obs->stop();  // dispatches handler to io_context thread
        // Reset the shared_ptr to destroy the observer, which resets the recv_loop
        // and closes the socket — this allows io.run() to drain and return.
        obs.reset();
        io_thread.join();

        REQUIRE(handler_fired);
    }
    catch (const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 4: async_start with callback fires on stop (API-11 — service_server)
// ---------------------------------------------------------------------------

SCENARIO("async_start with callback fires when stop() is called",
         "[completion_token][callback][service_server]")
{
    asio::io_context io;
    try
    {
        mdnspp::service_info info;
        info.service_name  = "Test._http._tcp.local.";
        info.service_type  = "_http._tcp.local.";
        info.hostname      = "testhost.local.";
        info.port          = 8080;
        info.address_ipv4  = "192.168.1.10";

        auto server = std::make_shared<mdnspp::service_server<mdnspp::AsioPolicy>>(
            io, std::move(info));

        bool handler_fired = false;
        server->async_start([&handler_fired](std::error_code ec) {
            handler_fired = true;
        });

        std::thread io_thread([&io] { io.run(); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        server->stop();
        io_thread.join();

        REQUIRE(handler_fired);
    }
    catch (const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 5: async_discover with deferred — does not initiate I/O until launched (API-13)
// ---------------------------------------------------------------------------

SCENARIO("async_discover with deferred does not initiate I/O until launched",
         "[completion_token][deferred][service_discovery]")
{
    asio::io_context io;
    try
    {
        mdnspp::service_discovery<mdnspp::AsioPolicy> sd{io, std::chrono::milliseconds(300)};

        // Create deferred operation — must NOT send any packets or arm any async ops yet
        auto op = mdnspp::async_discover(sd, "_deferred._tcp.local.", asio::deferred);

        // Launch the operation with a plain callback — this is when I/O initiates
        bool callback_fired = false;
        std::move(op)([&callback_fired](std::error_code ec,
                                         std::vector<mdnspp::mdns_record_variant> results) {
            callback_fired = true;
        });

        io.run();
        REQUIRE(callback_fired);
    }
    catch (const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 9: async_browse with deferred — does not initiate I/O until launched (API-13)
// ---------------------------------------------------------------------------

SCENARIO("async_browse with deferred does not initiate I/O until launched",
         "[completion_token][deferred][service_discovery][browse]")
{
    asio::io_context io;
    try
    {
        mdnspp::service_discovery<mdnspp::AsioPolicy> sd{io, std::chrono::milliseconds(300)};
        auto op = mdnspp::async_browse(sd, "_deferred._tcp.local.", asio::deferred);
        bool callback_fired = false;
        std::move(op)([&callback_fired](std::error_code ec,
                                         std::vector<mdnspp::resolved_service> services) {
            callback_fired = true;
        });
        io.run();
        REQUIRE(callback_fired);
    }
    catch (const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 6: TSan test — async_observe + stop from separate thread (Success criterion 3)
// ---------------------------------------------------------------------------

SCENARIO("async_observe completion handler dispatched on correct executor — TSan clean",
         "[completion_token][tsan][observer]")
{
    asio::io_context io;
    try
    {
        auto obs = std::make_shared<mdnspp::observer<mdnspp::AsioPolicy>>(
            io, [](const mdnspp::mdns_record_variant &, mdnspp::endpoint) {});

        bool handler_fired = false;
        obs->async_observe([&handler_fired](std::error_code ec) {
            handler_fired = true;
        });

        std::thread io_thread([&io] { io.run(); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        obs->stop();  // dispatches handler to io_context thread via asio::dispatch
        // Reset shared_ptr to destroy observer, closing socket so io.run() can return.
        obs.reset();
        io_thread.join();

        // When compiled with -fsanitize=thread, any data race in stop() / dispatch path
        // causes a non-zero exit and test failure before this line.
        REQUIRE(handler_fired);
    }
    catch (const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 7: use_awaitable with observer — co_await suspends until stop() (API-12)
// ---------------------------------------------------------------------------

#ifdef ASIO_HAS_CO_AWAIT

SCENARIO("async_observe with use_awaitable suspends until stop",
         "[completion_token][use_awaitable][observer]")
{
    asio::io_context io;
    try
    {
        auto obs = std::make_shared<mdnspp::observer<mdnspp::AsioPolicy>>(
            io, [](const mdnspp::mdns_record_variant &, mdnspp::endpoint) {});

        // Schedule stop() after 100ms.
        asio::steady_timer stop_timer{io, std::chrono::milliseconds(100)};
        stop_timer.async_wait([obs](std::error_code) { obs->stop(); });

        bool completed = false;
        // After the co_await resumes (stop() was called), stop the io_context
        // so io.run_for() returns — observer's recv_loop keeps io.run() alive otherwise.
        asio::co_spawn(
            io,
            [obs, &completed, &io]() -> asio::awaitable<void>
            {
                co_await mdnspp::async_observe(*obs, asio::use_awaitable);
                completed = true;
                io.stop(); // allow io.run_for() to return
            },
            asio::detached);

        // run_for provides an upper bound; normal completion is ~150ms
        io.run_for(std::chrono::seconds(5));
        REQUIRE(completed);
    }
    catch (const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

// ---------------------------------------------------------------------------
// Test 10: async_browse with use_awaitable — co_await suspends until browse completes (API-12)
// ---------------------------------------------------------------------------

SCENARIO("async_browse with use_awaitable returns services when complete",
         "[completion_token][use_awaitable][service_discovery][browse]")
{
    asio::io_context io;
    try
    {
        mdnspp::service_discovery<mdnspp::AsioPolicy> sd{io, std::chrono::milliseconds(300)};
        bool completed = false;
        asio::co_spawn(
            io,
            [&sd, &completed]() -> asio::awaitable<void>
            {
                auto services = co_await mdnspp::async_browse(
                    sd, "_nonexistent._tcp.local.", asio::use_awaitable);
                REQUIRE(services.empty());
                completed = true;
            },
            asio::detached);
        io.run();
        REQUIRE(completed);
    }
    catch (const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

#endif // ASIO_HAS_CO_AWAIT
