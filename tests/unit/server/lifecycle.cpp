#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

SCENARIO("service_server constructs with direct constructor", "[service_server][create]")
{
    GIVEN("a mock_executor")
    {
        mock_executor ex;

        WHEN("basic_service_server<MockPolicy> is constructed with a test service_info")
        {
            basic_service_server<MockPolicy> server{ex, make_test_info()};

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
        basic_service_server<MockPolicy> server{ex, make_test_info()};

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
        basic_service_server<MockPolicy> server{ex, make_test_info()};

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

        basic_service_server<MockPolicy> server{ex, make_test_info()};
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
        basic_service_server<MockPolicy> server{ex, make_test_info()};

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

        WHEN("basic_service_server<MockPolicy> is constructed with the ec overload")
        {
            basic_service_server<MockPolicy> server{ex, make_test_info(), {}, {}, {}, ec};

            THEN("ec is clear and the server is usable")
            {
                REQUIRE_FALSE(ec);
                REQUIRE(server.socket().queue_empty());
            }
        }
    }
}

SCENARIO("service_server is move-constructible before async_start", "[service_server][move]")
{
    GIVEN("a service_server constructed but not started")
    {
        mock_executor ex;
        basic_service_server<MockPolicy> server{ex, make_test_info()};

        WHEN("move-constructed into a new server")
        {
            basic_service_server<MockPolicy> moved{std::move(server)};

            THEN("the moved-to server is usable")
            {
                REQUIRE(moved.socket().queue_empty());
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
                basic_service_server<MockPolicy> server{ex, make_test_info()};
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
        basic_service_server<MockPolicy> server{ex, make_test_info()};
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

        WHEN("basic_service_server<MockPolicy> is constructed with socket_options")
        {
            basic_service_server<MockPolicy> server{ex, make_test_info(), {}, opts};

            THEN("the socket stores the options")
            {
                REQUIRE(server.socket().options().interface_address == "192.168.2.1");
                REQUIRE(server.socket().queue_empty());
            }
        }
    }
}
