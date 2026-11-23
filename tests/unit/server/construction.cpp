#include "helpers.h"

#include "mdnspp/detail/sibling_records.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <memory>
#include <string>
#include <utility>
#include <type_traits>
#include <system_error>

namespace {

struct checked_server
{
    checked_server(mock_executor &ex, service_info info, service_options opts, mdns_options mopts)
        : ec{}
        , server{ex, std::move(info), std::move(opts), {}, std::move(mopts), ec}
    {
    }

    std::error_code ec;
    basic_service_server<mock_policy> server;
};

void reports_invalid_argument(const checked_server &c)
{
    THEN("the error_code constructor reports invalid_argument")
    {
        REQUIRE(c.ec == std::errc::invalid_argument);
    }
}

void option_sections(mock_executor &ex)
{
    WHEN("probe_count is 0")
    {
        checked_server c{ex, make_test_info(), service_options{.probe_count = 0}, {}};
        reports_invalid_argument(c);
    }

    WHEN("response_delay_min exceeds response_delay_max")
    {
        mdns_options mopts;
        mopts.response_delay_min = std::chrono::milliseconds{200};
        mopts.response_delay_max = std::chrono::milliseconds{100};
        checked_server c{ex, make_test_info(), {}, std::move(mopts)};
        reports_invalid_argument(c);
    }

    WHEN("backoff_multiplier is below 1.0")
    {
        checked_server c{ex, make_test_info(), {}, mdns_options{.backoff_multiplier = 0.5}};
        reports_invalid_argument(c);
    }
}

void name_and_ttl_sections(mock_executor &ex)
{
    WHEN("a service name carries an oversized label")
    {
        auto info = make_test_info();
        info.service_name = std::string(70, 'x') + "._http._tcp.local.";
        checked_server c{ex, std::move(info), {}, {}};
        reports_invalid_argument(c);
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

SCENARIO("constructor validates options", "[service_server][validation]")
{
    GIVEN("a mock_executor")
    {
        mock_executor ex;
        option_sections(ex);
        name_and_ttl_sections(ex);
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

SCENARIO("service_server error_code constructor with siblings reports errors", "[service_server][create][non-throwing]")
{
    GIVEN("a mock_executor and a sibling registry")
    {
        mock_executor ex;
        auto siblings = std::make_shared<detail::sibling_records>();
        std::error_code ec;

        WHEN("an option is invalid")
        {
            basic_service_server<mock_policy> server{ex, make_test_info(), service_options{.probe_count = 0}, {}, {},
                                                     siblings, 0, ec};

            THEN("ec reports invalid_argument")
            {
                REQUIRE(ec == std::errc::invalid_argument);
            }
        }
    }
}
