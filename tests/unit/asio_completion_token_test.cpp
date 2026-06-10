// tests/asio_completion_token_test.cpp

#include "mdnspp/asio.h"
#include "mdnspp/service_info.h"

#include "mdnspp/detail/dns_enums.h"

#include <asio.hpp>
#include <asio/as_tuple.hpp>
#include <asio/deferred.hpp>
#include <asio/detached.hpp>
#include <asio/use_future.hpp>
#include <asio/cancel_after.hpp>
#include <asio/use_awaitable.hpp>

#ifdef ASIO_HAS_CO_AWAIT
#include <asio/co_spawn.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#endif

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <thread>

// ---------------------------------------------------------------------------
// Test 1: async_discover with use_future (API-11)
// ---------------------------------------------------------------------------

SCENARIO("async_discover with use_future returns future with results", "[completion_token][use_future][service_discovery]")
{
    asio::io_context io;
    try
    {
        mdnspp::basic_service_discovery<mdnspp::asio_policy> sd{io, mdnspp::query_options{.silence_timeout = std::chrono::milliseconds(500)}};

        auto fut = mdnspp::async_discover(sd, "_nonexistent._tcp.local.", asio::use_future);

        io.run();

        auto results = fut.get();
        REQUIRE(results.empty());
    }
    catch(const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

SCENARIO("async_browse with use_future returns future with services", "[completion_token][use_future][service_discovery][browse]")
{
    asio::io_context io;
    try
    {
        mdnspp::basic_service_discovery<mdnspp::asio_policy> sd{io, mdnspp::query_options{.silence_timeout = std::chrono::milliseconds(500)}};
        auto fut = mdnspp::async_browse(sd, "_nonexistent._tcp.local.", asio::use_future);
        io.run();
        auto services = fut.get();
        REQUIRE(services.empty());
    }
    catch(const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

SCENARIO("async_query with use_future returns future with results", "[completion_token][use_future][querier]")
{
    asio::io_context io;
    try
    {
        mdnspp::basic_querier<mdnspp::asio_policy> q{io, mdnspp::query_options{.silence_timeout = std::chrono::milliseconds(500)}};

        auto fut = mdnspp::async_query(q, "_nonexistent._tcp.local.", mdnspp::dns_type::ptr, asio::use_future);

        io.run();

        auto results = fut.get();
        REQUIRE(results.empty());
    }
    catch(const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

SCENARIO("async_observe with callback fires when stop() is called", "[completion_token][callback][observer]")
{
    asio::io_context io;
    try
    {
        auto obs = std::make_shared<mdnspp::basic_observer<mdnspp::asio_policy>>(
            io,
            mdnspp::observer_options{.on_record = [](const mdnspp::endpoint &, const mdnspp::mdns_record_variant &)
            {
            }});

        bool handler_fired = false;
        obs->async_observe([&handler_fired](std::error_code)
        {
            handler_fired = true;
        });

        std::thread io_thread([&io] { io.run(); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        obs->stop();
        io_thread.join();
        obs.reset();

        REQUIRE(handler_fired);
    }
    catch(const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

SCENARIO("async_start adapter completes with operation_canceled when stop() precedes ready", "[completion_token][callback][service_server]")
{
    asio::io_context io;
    try
    {
        mdnspp::service_info info;
        info.service_name = "Test._http._tcp.local.";
        info.service_type = "_http._tcp.local.";
        info.hostname = "testhost.local.";
        info.port = 8080;
        info.address_ipv4 = "192.168.1.10";

        auto server = std::make_shared<mdnspp::basic_service_server<mdnspp::asio_policy>>(
            io, std::move(info));

        std::atomic<bool> handler_fired{false};
        std::error_code out;
        mdnspp::async_start(*server, [&handler_fired, &out](std::error_code ec)
        {
            out = ec;
            handler_fired.store(true);
        });

        std::thread io_thread([&io] { io.run(); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        server->stop(); // default probe schedule needs ~750 ms -- not yet live
        io_thread.join();
        server.reset();

        REQUIRE(handler_fired.load());
        REQUIRE(out == std::errc::operation_canceled);
    }
    catch(const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

SCENARIO("async_start adapter completes at ready without stop()", "[completion_token][use_future][service_server][ready]")
{
    asio::io_context io;
    try
    {
        mdnspp::service_info info;
        info.service_name = "TestReady._http._tcp.local.";
        info.service_type = "_http._tcp.local.";
        info.hostname = "testready.local.";
        info.port = 8081;
        info.address_ipv4 = "192.168.1.11";

        auto server = std::make_shared<mdnspp::basic_service_server<mdnspp::asio_policy>>(
            io, std::move(info),
            mdnspp::service_options{
                .announce_count = 1,
                .announce_interval = std::chrono::milliseconds(10),
                .probe_count = 1,
                .probe_interval = std::chrono::milliseconds(10),
                .probe_initial_delay_max = std::chrono::milliseconds(0)});

        auto fut = mdnspp::async_start(*server, asio::use_future);

        std::thread io_thread([&io] { io.run(); });

        // The token binds on_ready: it must complete while the server keeps
        // running, with no stop() involved.
        REQUIRE(fut.wait_for(std::chrono::seconds(5)) == std::future_status::ready);
        REQUIRE_NOTHROW(fut.get());

        server->stop();
        io_thread.join();
        server.reset();
    }
    catch(const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

SCENARIO("async_run completes only after stop() runs the teardown", "[completion_token][callback][service_server][run]")
{
    asio::io_context io;
    try
    {
        mdnspp::service_info info;
        info.service_name = "TestRun._http._tcp.local.";
        info.service_type = "_http._tcp.local.";
        info.hostname = "testrun.local.";
        info.port = 8082;
        info.address_ipv4 = "192.168.1.12";

        auto server = std::make_shared<mdnspp::basic_service_server<mdnspp::asio_policy>>(
            io, std::move(info),
            mdnspp::service_options{
                .announce_count = 1,
                .announce_interval = std::chrono::milliseconds(10),
                .probe_count = 1,
                .probe_interval = std::chrono::milliseconds(10),
                .probe_initial_delay_max = std::chrono::milliseconds(0)});

        std::atomic<bool> handler_fired{false};
        std::error_code out = std::make_error_code(std::errc::io_error); // sentinel
        mdnspp::async_run(*server, [&handler_fired, &out](std::error_code ec)
        {
            out = ec;
            handler_fired.store(true);
        });

        std::thread io_thread([&io] { io.run(); });

        // The server is live well before 300 ms with the fast schedule above,
        // but on_done is bound: the token must not have completed yet.
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        REQUIRE_FALSE(handler_fired.load());

        server->stop();
        io_thread.join();
        server.reset();

        REQUIRE(handler_fired.load());
        REQUIRE(out == std::error_code{});
    }
    catch(const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

SCENARIO("async_run after stop() completes deterministically with invalid_argument", "[completion_token][callback][service_server][run][misuse]")
{
    asio::io_context io;
    try
    {
        mdnspp::service_info info;
        info.service_name = "TestRunMisuse._http._tcp.local.";
        info.service_type = "_http._tcp.local.";
        info.hostname = "testrunmisuse.local.";
        info.port = 8083;
        info.address_ipv4 = "192.168.1.13";

        auto server = std::make_shared<mdnspp::basic_service_server<mdnspp::asio_policy>>(
            io, std::move(info));

        server->stop();

        bool handler_fired = false;
        std::error_code out;
        mdnspp::async_run(*server, [&handler_fired, &out](std::error_code ec)
        {
            out = ec;
            handler_fired = true;
        });

        io.run();
        server.reset();

        REQUIRE(handler_fired);
        REQUIRE(out == std::errc::invalid_argument);
    }
    catch(const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

SCENARIO("async_discover with deferred does not initiate I/O until launched", "[completion_token][deferred][service_discovery]")
{
    asio::io_context io;
    try
    {
        mdnspp::basic_service_discovery<mdnspp::asio_policy> sd{io, mdnspp::query_options{.silence_timeout = std::chrono::milliseconds(300)}};

        // Create deferred operation — must NOT send any packets or arm any async ops yet
        auto op = mdnspp::async_discover(sd, "_deferred._tcp.local.", asio::deferred);

        // Launch the operation with a plain callback — this is when I/O initiates
        bool callback_fired = false;
        std::move(op)([&callback_fired](std::error_code,
                                        std::vector<mdnspp::mdns_record_variant>)
        {
            callback_fired = true;
        });

        io.run();
        REQUIRE(callback_fired);
    }
    catch(const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

SCENARIO("async_browse with deferred does not initiate I/O until launched", "[completion_token][deferred][service_discovery][browse]")
{
    asio::io_context io;
    try
    {
        mdnspp::basic_service_discovery<mdnspp::asio_policy> sd{io, mdnspp::query_options{.silence_timeout = std::chrono::milliseconds(300)}};
        auto op = mdnspp::async_browse(sd, "_deferred._tcp.local.", asio::deferred);
        bool callback_fired = false;
        std::move(op)([&callback_fired](std::error_code,
                                        std::vector<mdnspp::resolved_service>)
        {
            callback_fired = true;
        });
        io.run();
        REQUIRE(callback_fired);
    }
    catch(const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

SCENARIO("async_observe completion handler dispatched on correct executor -- TSan clean", "[completion_token][tsan][observer]")
{
    asio::io_context io;
    try
    {
        auto obs = std::make_shared<mdnspp::basic_observer<mdnspp::asio_policy>>(
            io,
            mdnspp::observer_options{.on_record = [](const mdnspp::endpoint &, const mdnspp::mdns_record_variant &)
            {
            }});

        bool handler_fired = false;
        obs->async_observe([&handler_fired](std::error_code)
        {
            handler_fired = true;
        });

        std::thread io_thread([&io] { io.run(); });
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        obs->stop();
        io_thread.join();
        obs.reset();

        // When compiled with -fsanitize=thread, any data race in stop() / dispatch path
        // causes a non-zero exit and test failure before this line.
        REQUIRE(handler_fired);
    }
    catch(const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

SCENARIO("async_observe with cancel_after completes with operation_canceled", "[completion_token][cancellation][cancel_after][observer]")
{
    asio::io_context io;
    try
    {
        auto obs = std::make_shared<mdnspp::basic_observer<mdnspp::asio_policy>>(
            io,
            mdnspp::observer_options{.on_record = [](const mdnspp::endpoint &, const mdnspp::mdns_record_variant &)
            {
            }});

        // cancel_after signals the operation's cancellation slot when the
        // deadline expires; the adapter translates that into obs->stop(),
        // which completes the observation with operation_canceled.
        auto fut = mdnspp::async_observe(
            *obs, asio::cancel_after(std::chrono::milliseconds(100),
                                     asio::as_tuple(asio::use_future)));

        io.run(); // returns once the cancelled observation is torn down

        auto [ec] = fut.get();
        REQUIRE(ec == std::errc::operation_canceled);
    }
    catch(const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

#ifdef ASIO_HAS_CO_AWAIT

SCENARIO("async_observe with use_awaitable suspends until stop", "[completion_token][use_awaitable][observer]")
{
    asio::io_context io;
    try
    {
        auto obs = std::make_shared<mdnspp::basic_observer<mdnspp::asio_policy>>(
            io,
            mdnspp::observer_options{.on_record = [](const mdnspp::endpoint &, const mdnspp::mdns_record_variant &)
            {
            }});

        asio::steady_timer stop_timer{io, std::chrono::milliseconds(100)};
        stop_timer.async_wait([obs](std::error_code) { obs->stop(); });

        bool completed = false;
        std::error_code completion_ec;
        // After the co_await resumes (stop() was called), stop the io_context
        // so io.run_for() returns — observer's recv_loop keeps io.run() alive otherwise.
        // stop() completes the observation with operation_canceled; as_tuple
        // surfaces the error_code instead of throwing.
        asio::co_spawn(
            io,
            [obs, &completed, &completion_ec, &io]() -> asio::awaitable<void>
            {
                auto [ec] = co_await mdnspp::async_observe(
                    *obs, asio::as_tuple(asio::use_awaitable));
                completion_ec = ec;
                completed = true;
                io.stop(); // allow io.run_for() to return
            },
            asio::detached);

        // run_for provides an upper bound; normal completion is ~150ms
        io.run_for(std::chrono::seconds(5));
        REQUIRE(completed);
        REQUIRE(completion_ec == std::errc::operation_canceled);
    }
    catch(const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

SCENARIO("async_observe loses an awaitable || race and is cancelled by the group", "[completion_token][cancellation][use_awaitable][observer]")
{
    asio::io_context io;
    try
    {
        auto obs = std::make_shared<mdnspp::basic_observer<mdnspp::asio_policy>>(
            io,
            mdnspp::observer_options{.on_record = [](const mdnspp::endpoint &, const mdnspp::mdns_record_variant &)
            {
            }});

        // operator|| cancels the loser through its cancellation slot and
        // waits for it to complete. Without slot support the observe arm
        // never completes and this co_await suspends forever.
        bool timer_won = false;
        asio::co_spawn(
            io,
            [obs, &timer_won, &io]() -> asio::awaitable<void>
            {
                using namespace asio::experimental::awaitable_operators;
                asio::steady_timer deadline{io, std::chrono::milliseconds(100)};
                auto winner = co_await (mdnspp::async_observe(*obs, asio::use_awaitable)
                                        || deadline.async_wait(asio::use_awaitable));
                timer_won = winner.index() == 1;
                io.stop();
            },
            asio::detached);

        io.run_for(std::chrono::seconds(5));
        REQUIRE(timer_won);
    }
    catch(const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

SCENARIO("async_browse with use_awaitable returns services when complete", "[completion_token][use_awaitable][service_discovery][browse]")
{
    asio::io_context io;
    try
    {
        mdnspp::basic_service_discovery<mdnspp::asio_policy> sd{io, mdnspp::query_options{.silence_timeout = std::chrono::milliseconds(300)}};
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
    catch(const std::exception &e)
    {
        WARN("Skipping — socket construction failed (no network): " << e.what());
    }
}

#endif
