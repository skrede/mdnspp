#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <utility>
#include <type_traits>
#include <system_error>

namespace {

mdns_options inverted_delay_options()
{
    mdns_options bad;
    bad.response_delay_min = 200ms;
    bad.response_delay_max = 100ms;
    return bad;
}

void ec_overload_rejects(mock_executor &ex, query_options opts, mdns_options mdns_opts)
{
    WHEN("constructed with the ec overload")
    {
        std::error_code ec;
        basic_querier<mock_policy> q{ex, std::move(opts), {}, std::move(mdns_opts), ec};

        THEN("ec is invalid_argument")
        {
            REQUIRE(ec == std::errc::invalid_argument);
        }
    }
}

}

SCENARIO("querier constructs and is usable", "[querier][create]")
{
    GIVEN("a querier instance with mock_policy")
    {
        mock_executor ex;

        WHEN("constructed with 500ms silence timeout")
        {
            basic_querier<mock_policy> q{ex, query_options{.silence_timeout = 500ms}};

            THEN("it is usable (socket is empty, results empty)")
            {
                REQUIRE(q.socket().queue_empty());
                REQUIRE(q.results().empty());
            }
        }
    }
}

SCENARIO("querier non-throwing constructor sets ec on success", "[querier][create][non-throwing]")
{
    GIVEN("a mock_executor and an error_code")
    {
        mock_executor ex;
        std::error_code ec;

        WHEN("basic_querier<mock_policy> is constructed with the ec overload")
        {
            basic_querier<mock_policy> q{ex, query_options{.silence_timeout = 500ms}, {}, {}, ec};

            THEN("ec is clear and the querier is usable")
            {
                REQUIRE_FALSE(ec);
                REQUIRE(q.socket().queue_empty());
                REQUIRE(q.results().empty());
            }
        }
    }
}

SCENARIO("querier is neither copyable nor movable", "[querier][move]")
{
    STATIC_REQUIRE_FALSE(std::is_copy_constructible_v<basic_querier<mock_policy>>);
    STATIC_REQUIRE_FALSE(std::is_copy_assignable_v<basic_querier<mock_policy>>);
    STATIC_REQUIRE_FALSE(std::is_move_constructible_v<basic_querier<mock_policy>>);
    STATIC_REQUIRE_FALSE(std::is_move_assignable_v<basic_querier<mock_policy>>);
}

SCENARIO("querier constructor rejects invalid options", "[querier][validate]")
{
    GIVEN("response_delay_min greater than response_delay_max")
    {
        mock_executor ex;
        mdns_options bad = inverted_delay_options();
        ec_overload_rejects(ex, query_options{.silence_timeout = 500ms}, bad);

        WHEN("constructed with the throwing overload")
        {
            THEN("std::system_error is thrown")
            {
                REQUIRE_THROWS_AS((basic_querier<mock_policy>{ex, query_options{.silence_timeout = 500ms}, {}, bad}),
                                  std::system_error);
            }
        }
    }

    GIVEN("a non-positive silence timeout")
    {
        mock_executor ex;
        ec_overload_rejects(ex, query_options{.silence_timeout = 0ms}, {});
    }
}

SCENARIO("basic_querier with socket_options", "[querier][socket_options]")
{
    GIVEN("a socket_options with multicast_ttl = 100")
    {
        mock_executor ex;
        socket_options opts{.multicast_ttl = uint8_t{100}};

        WHEN("basic_querier<mock_policy> is constructed with socket_options")
        {
            basic_querier<mock_policy> q{ex, query_options{.silence_timeout = 500ms}, opts};

            THEN("the socket stores the options with ttl = 100")
            {
                REQUIRE(q.socket().options().multicast_ttl == 100);
                REQUIRE(q.socket().queue_empty());
                REQUIRE(q.results().empty());
            }
        }
    }
}
