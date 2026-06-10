#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <type_traits>
#include <system_error>

SCENARIO("service_server constructs with direct constructor", "[service_server][create]")
{
    GIVEN("a mock_executor")
    {
        mock_executor ex;

        WHEN("basic_service_server<mock_policy> is constructed with a test service_info")
        {
            basic_service_server<mock_policy> server{ex, make_test_info()};

            THEN("the server is constructed successfully (socket is accessible)")
            {
                REQUIRE(server.socket().queue_empty());
            }
        }
    }
}

SCENARIO("async_start and stop lifecycle", "[service_server][lifecycle]")
{
    GIVEN("a service_server with no enqueued queries")
    {
        mock_executor ex;
        basic_service_server<mock_policy> server{ex, make_test_info()};

        WHEN("async_start() is called")
        {
            server.async_start();

            THEN("stop() can be called without error")
            {
                REQUIRE_NOTHROW(server.stop());

                AND_THEN("stop() can be called again (idempotent)")
                {
                    REQUIRE_NOTHROW(server.stop());
                }
            }
        }
    }
}

SCENARIO("async_start fires completion callback on stop", "[service_server][async]")
{
    GIVEN("a service_server with no enqueued queries")
    {
        mock_executor ex;
        basic_service_server<mock_policy> server{ex, make_test_info()};

        WHEN("async_start() is called with on_done completion callback")
        {
            std::error_code received_ec;
            bool callback_fired = false;

            server.async_start({}, [&](std::error_code ec)
            {
                callback_fired = true;
                received_ec = ec;
            });

            AND_WHEN("stop() is called")
            {
                server.stop();
                ex.drain_posted();

                THEN("the on_done callback fires with error_code{}")
                {
                    REQUIRE(callback_fired);
                    REQUIRE_FALSE(received_ec);
                }
            }
        }
    }
}

SCENARIO("async_start completion handler fires exactly once on double stop", "[service_server][stop-idempotent][completion]")
{
    GIVEN("a started service_server with on_done callback")
    {
        mock_executor ex;
        int completion_count = 0;

        basic_service_server<mock_policy> server{ex, make_test_info()};
        server.async_start({}, [&](std::error_code) { ++completion_count; });

        // Advance to live so stop doesn't fire on_ready
        advance_to_live(server);

        WHEN("stop() is called twice")
        {
            server.stop();
            server.stop();
            ex.drain_posted();

            THEN("the on_done callback fires exactly once")
            {
                REQUIRE(completion_count == 1);
            }
        }
    }
}

SCENARIO("stop before timer fires prevents response", "[service_server][stop][cancel]")
{
    GIVEN("a service_server that has been started")
    {
        mock_executor ex;
        basic_service_server<mock_policy> server{ex, make_test_info()};

        WHEN("async_start() is called then stop() is called during probing")
        {
            server.async_start();
            server.stop();

            AND_WHEN("timer().fire() is called (simulating a late fire after cancel)")
            {
                server.timer().fire();

                THEN("no response or announcement is sent after stop")
                {
                    // Only packets sent before stop are probe-related
                    // After stop, no more packets should be sent
                    auto sent_before = server.socket().sent_packets().size();
                    server.timer().fire(); // another late fire
                    REQUIRE(server.socket().sent_packets().size() == sent_before);
                }
            }
        }
    }
}

SCENARIO("service_server non-throwing constructor sets ec on success", "[service_server][create][non-throwing]")
{
    GIVEN("a mock_executor and an error_code")
    {
        mock_executor ex;
        std::error_code ec;

        WHEN("basic_service_server<mock_policy> is constructed with the ec overload")
        {
            basic_service_server<mock_policy> server{ex, make_test_info(), {}, {}, {}, ec};

            THEN("ec is clear and the server is usable")
            {
                REQUIRE_FALSE(ec);
                REQUIRE(server.socket().queue_empty());
            }
        }
    }
}

SCENARIO("service_server is neither copyable nor movable", "[service_server][move]")
{
    STATIC_CHECK_FALSE(std::is_copy_constructible_v<basic_service_server<mock_policy>>);
    STATIC_CHECK_FALSE(std::is_copy_assignable_v<basic_service_server<mock_policy>>);
    STATIC_CHECK_FALSE(std::is_move_constructible_v<basic_service_server<mock_policy>>);
    STATIC_CHECK_FALSE(std::is_move_assignable_v<basic_service_server<mock_policy>>);
}

SCENARIO("async_start is one-shot", "[service_server][one-shot]")
{
    GIVEN("a started service_server")
    {
        mock_executor ex;
        basic_service_server<mock_policy> server{ex, make_test_info()};
        server.async_start();

        WHEN("async_start is called a second time")
        {
            bool ready_fired = false;
            std::error_code ready_ec;
            server.async_start([&](std::error_code ec)
            {
                ready_fired = true;
                ready_ec = ec;
            });

            THEN("on_ready completes with operation_in_progress")
            {
                REQUIRE(ready_fired);
                REQUIRE(ready_ec == std::errc::operation_in_progress);
            }
        }

        WHEN("async_start is called after stop()")
        {
            server.stop();
            ex.drain_posted();

            bool ready_fired = false;
            std::error_code ready_ec;
            server.async_start([&](std::error_code ec)
            {
                ready_fired = true;
                ready_ec = ec;
            });

            THEN("on_ready completes with invalid_argument")
            {
                REQUIRE(ready_fired);
                REQUIRE(ready_ec == std::errc::invalid_argument);
            }
        }
    }
}

SCENARIO("constructor validates options", "[service_server][validation]")
{
    GIVEN("a mock_executor")
    {
        mock_executor ex;

        WHEN("probe_count is 0")
        {
            service_options opts;
            opts.probe_count = 0;
            std::error_code ec;
            basic_service_server<mock_policy> server{ex, make_test_info(), std::move(opts), {}, {}, ec};

            THEN("the error_code constructor reports invalid_argument")
            {
                REQUIRE(ec == std::errc::invalid_argument);
            }
        }

        WHEN("response_delay_min exceeds response_delay_max")
        {
            mdns_options mopts;
            mopts.response_delay_min = std::chrono::milliseconds{200};
            mopts.response_delay_max = std::chrono::milliseconds{100};
            std::error_code ec;
            basic_service_server<mock_policy> server{ex, make_test_info(), {}, {}, std::move(mopts), ec};

            THEN("the error_code constructor reports invalid_argument")
            {
                REQUIRE(ec == std::errc::invalid_argument);
            }
        }

        WHEN("backoff_multiplier is below 1.0")
        {
            mdns_options mopts;
            mopts.backoff_multiplier = 0.5;
            std::error_code ec;
            basic_service_server<mock_policy> server{ex, make_test_info(), {}, {}, std::move(mopts), ec};

            THEN("the error_code constructor reports invalid_argument")
            {
                REQUIRE(ec == std::errc::invalid_argument);
            }
        }

        WHEN("a service name carries an oversized label")
        {
            auto info = make_test_info();
            info.service_name = std::string(70, 'x') + "._http._tcp.local.";
            std::error_code ec;
            basic_service_server<mock_policy> server{ex, std::move(info), {}, {}, {}, ec};

            THEN("the error_code constructor reports invalid_argument")
            {
                REQUIRE(ec == std::errc::invalid_argument);
            }
        }

        WHEN("a ttl is zero")
        {
            service_options opts;
            opts.srv_ttl = std::chrono::seconds{0};

            THEN("the throwing constructor throws std::system_error")
            {
                REQUIRE_THROWS_AS(
                    (basic_service_server<mock_policy>{ex, make_test_info(), std::move(opts)}),
                    std::system_error);
            }
        }
    }
}

SCENARIO("liveness guard prevents use-after-free on server destruction", "[service_server][update][liveness]")
{
    GIVEN("a mock_executor outliving the server")
    {
        mock_executor ex;

        WHEN("a server posts update_service_info() then is destroyed before drain")
        {
            {
                basic_service_server<mock_policy> server{ex, make_test_info()};
                server.async_start();
                advance_to_live(server);
                server.update_service_info(make_test_info());
                // server destroyed here
            }

            THEN("draining posted work does not crash (liveness guard skips)")
            {
                REQUIRE_NOTHROW(ex.drain_posted());
            }
        }
    }
}

SCENARIO("stop discards pending posted work", "[service_server][update][stop]")
{
    GIVEN("a live service_server with posted update_service_info")
    {
        mock_executor ex;
        // send_goodbye=false so the only packet the posted teardown could send
        // (the goodbye) does not mask a wrongly-executed announcement.
        basic_service_server<mock_policy> server{ex, make_test_info(),
            service_options{.send_goodbye = false}};
        server.async_start();
        advance_to_live(server);
        server.update_service_info(make_test_info());

        WHEN("stop() is called then posted work is drained")
        {
            server.stop();
            server.socket().clear_sent();
            ex.drain_posted();

            THEN("no announcement was sent after stop")
            {
                REQUIRE(server.socket().sent_packets().empty());
            }
        }
    }
}

SCENARIO("basic_service_server with socket_options", "[service_server][socket_options]")
{
    GIVEN("a socket_options with a specific interface address")
    {
        mock_executor ex;
        socket_options opts{.interface_address = "192.168.2.1"};

        WHEN("basic_service_server<mock_policy> is constructed with socket_options")
        {
            basic_service_server<mock_policy> server{ex, make_test_info(), {}, opts};

            THEN("the socket stores the options")
            {
                REQUIRE(server.socket().options().interface_address == "192.168.2.1");
                REQUIRE(server.socket().queue_empty());
            }
        }
    }
}
