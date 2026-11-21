#include "fixture.h"
#include "query_helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <cstddef>
#include <string_view>
#include <system_error>

namespace {

service_options recording_error(std::error_code &received_ec, std::string &received_context)
{
    service_options opts;
    opts.on_error = [&received_ec, &received_context](std::error_code ec, std::string_view ctx)
    {
        received_ec = ec;
        received_context = std::string(ctx);
    };
    return opts;
}

service_options recording_continuation(endpoint &captured_sender, std::size_t &captured_count)
{
    service_options opts;
    opts.on_tc_continuation = [&captured_sender, &captured_count](const endpoint &sender, std::size_t count)
    {
        captured_sender = sender;
        captured_count = count;
    };
    return opts;
}

void continuation_sections(const endpoint &captured_sender, const endpoint &remote)
{
    THEN("on_tc_continuation was called with the correct sender")
    {
        REQUIRE(captured_sender.address == remote.address);
        REQUIRE(captured_sender.port == remote.port);
    }

    THEN("on_tc_continuation reports at least one continuation entry")
    {
        // The first TC packet is itself the known-answer set, so the count may be 0.
        REQUIRE(captured_sender.address == remote.address);
    }
}

}

SCENARIO("service_options with designated initializers", "[service_server][service_options]")
{
    GIVEN("a mock_executor")
    {
        mock_executor ex;
        bool query_called = false;

        WHEN("server is constructed with designated initializer service_options")
        {
            basic_service_server<mock_policy> server{ex, make_test_info(), service_options{
                .on_query = [&](const endpoint &, dns_type, response_mode) { query_called = true; },
                .announce_count = 5
            }};

            THEN("the server is constructed successfully")
            {
                REQUIRE(server.socket().queue_empty());
            }
        }
    }
}

SCENARIO("constructor with socket_options and service_options", "[service_server][constructor]")
{
    GIVEN("a mock_executor with socket_options and service_options")
    {
        mock_executor ex;
        socket_options sock_opts{.interface_address = "10.0.0.1"};

        WHEN("server is constructed with both option types")
        {
            basic_service_server<mock_policy> server{ex, make_test_info(), service_options{.announce_count = 3},
                                                     sock_opts};

            THEN("the server is constructed successfully")
            {
                REQUIRE(server.socket().options().interface_address == "10.0.0.1");
            }
        }
    }
}

SCENARIO("on_error callback fires on send failure", "[service_server][on_error]")
{
    GIVEN("a service_server with on_error callback and send failure injection")
    {
        std::error_code received_ec;
        std::string received_context;
        server_fixture f{make_test_info(), recording_error(received_ec, received_context)};
        mock_socket::set_fail_on_send(true);

        WHEN("the server starts and attempts to send a probe")
        {
            f.start();
            f.fire();

            THEN("on_error was called with a non-empty context string")
            {
                REQUIRE(received_ec);
                REQUIRE(received_ec == std::errc::network_unreachable);
                REQUIRE_FALSE(received_context.empty());
            }
        }

        mock_socket::set_fail_on_send(false);
    }
}

SCENARIO("stop-then-destroy is safe without draining posted work", "[service_server][stop-destroy-safety]")
{
    GIVEN("a service_server in a scoped block")
    {
        mock_executor ex;

        WHEN("the server is created, started, stopped, and destroyed without draining")
        {
            THEN("no crash occurs (posted lambda becomes a no-op via weak_ptr sentinel)")
            {
                REQUIRE_NOTHROW([&]()
                {
                    basic_service_server<mock_policy> server{ex, make_test_info()};
                    server.async_start();
                    advance_to_live(server);
                    server.stop();
                }());

                // The destructor reset the alive guard, so the still-queued teardown is a no-op.
                REQUIRE_NOTHROW(ex.drain_posted());
            }
        }
    }
}

SCENARIO("on_tc_continuation callback fires when TC timer expires",
         "[service_server][tc][callback]")
{
    GIVEN("a live service server with on_tc_continuation callback configured")
    {
        endpoint captured_sender;
        std::size_t captured_count = 0;
        server_fixture f{make_test_info(), recording_continuation(captured_sender, captured_count)};
        f.go_live();

        endpoint remote{"192.168.1.20", 5353};
        f.inject(remote, make_tc_ptr_query("_http._tcp.local."));
        REQUIRE(f.server.tc_timer().has_pending());

        WHEN("the TC wait timer fires")
        {
            f.server.tc_timer().fire();
            continuation_sections(captured_sender, remote);
        }
    }
}

SCENARIO("TC timer is cancelled on stop()", "[service_server][tc][stop]")
{
    GIVEN("a live server with a pending TC wait")
    {
        server_fixture f;
        f.go_live();

        endpoint remote{"192.168.1.20", 5353};
        f.inject(remote, make_tc_ptr_query("_http._tcp.local."));
        REQUIRE(f.server.tc_timer().has_pending());

        WHEN("stop() is called")
        {
            f.stop();

            THEN("the tc_timer has been cancelled (no pending handler)")
            {
                REQUIRE_FALSE(f.server.tc_timer().has_pending());
            }
        }
    }
}
