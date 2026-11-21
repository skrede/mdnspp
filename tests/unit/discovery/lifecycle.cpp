#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <type_traits>
#include <system_error>

namespace {

void natural_or_stopped_sections(discovery_fixture &f)
{
    WHEN("the silence timer fires (natural completion)")
    {
        f.fire_silence();

        THEN("the completion fires with success")
        {
            check_completed(f.found);
        }
    }

    WHEN("stop() is called before the silence timeout")
    {
        f.stop();

        THEN("the completion fires with operation_canceled")
        {
            check_completed_with(f.found, std::errc::operation_canceled);
        }
    }
}

}

SCENARIO("service_discovery non-throwing constructor sets ec on success", "[service_discovery][create][non-throwing]")
{
    GIVEN("a mock_executor and an error_code")
    {
        mock_executor ex;
        std::error_code ec;

        WHEN("basic_service_discovery<mock_policy> is constructed with the ec overload")
        {
            basic_service_discovery<mock_policy> sd{ex, query_options{.silence_timeout = 500ms}, {}, {}, ec};

            THEN("ec is clear and the service_discovery is usable")
            {
                REQUIRE_FALSE(ec);
                REQUIRE(sd.socket().queue_empty());
                REQUIRE(sd.results().empty());
            }
        }
    }
}

SCENARIO("service_discovery is neither copyable nor movable", "[service_discovery][move]")
{
    STATIC_REQUIRE_FALSE(std::is_copy_constructible_v<basic_service_discovery<mock_policy>>);
    STATIC_REQUIRE_FALSE(std::is_copy_assignable_v<basic_service_discovery<mock_policy>>);
    STATIC_REQUIRE_FALSE(std::is_move_constructible_v<basic_service_discovery<mock_policy>>);
    STATIC_REQUIRE_FALSE(std::is_move_assignable_v<basic_service_discovery<mock_policy>>);
}

SCENARIO("stop() vs natural completion error codes", "[service_discovery][stop][cancel]")
{
    GIVEN("a service_discovery with a PTR response enqueued")
    {
        discovery_fixture f;
        f.enqueue(make_ptr_response("_http._tcp.local.", "Svc._http._tcp.local."));
        f.discover(record_into(f.found));
        natural_or_stopped_sections(f);
    }
}

SCENARIO("destruction with a pending discover completes the handler with operation_canceled", "[service_discovery][destructor]")
{
    GIVEN("a started discovery that is destroyed without completing")
    {
        mock_executor ex;
        discover_outcome done;
        {
            basic_service_discovery<mock_policy> sd{ex, query_options{.silence_timeout = 500ms}};
            sd.async_discover("_http._tcp.local.", record_into(done));
        }

        THEN("the completion handler fired with operation_canceled")
        {
            check_completed_with(done, std::errc::operation_canceled);
        }
    }
}

SCENARIO("basic_service_discovery with socket_options", "[service_discovery][socket_options]")
{
    GIVEN("a socket_options with a specific interface address")
    {
        mock_executor ex;
        socket_options opts{.interface_address = "172.16.0.1"};

        WHEN("basic_service_discovery<mock_policy> is constructed with socket_options")
        {
            basic_service_discovery<mock_policy> sd{ex, query_options{.silence_timeout = 500ms}, opts};

            THEN("the socket stores the options")
            {
                REQUIRE(sd.socket().options().interface_address == "172.16.0.1");
                REQUIRE(sd.socket().queue_empty());
                REQUIRE(sd.results().empty());
            }
        }
    }
}
