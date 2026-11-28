#include "helpers.h"

#include <type_traits>
#include <system_error>

SCENARIO("observer non-throwing constructor sets ec on success", "[observer][create][non-throwing]")
{
    GIVEN("a mock_executor and an error_code")
    {
        mock_executor ex;
        std::error_code ec;

        WHEN("basic_observer<mock_policy> is constructed with the ec overload")
        {
            basic_observer<mock_policy> obs{ex, ignore_records(), {}, {}, ec};

            THEN("ec is clear and the observer is usable")
            {
                REQUIRE_FALSE(ec);
                REQUIRE(obs.socket().queue_empty());
            }
        }
    }
}

SCENARIO("observer is neither copyable nor movable", "[observer][move]")
{
    STATIC_REQUIRE_FALSE(std::is_copy_constructible_v<basic_observer<mock_policy>>);
    STATIC_REQUIRE_FALSE(std::is_copy_assignable_v<basic_observer<mock_policy>>);
    STATIC_REQUIRE_FALSE(std::is_move_constructible_v<basic_observer<mock_policy>>);
    STATIC_REQUIRE_FALSE(std::is_move_assignable_v<basic_observer<mock_policy>>);
}

SCENARIO("destruction with a pending observation completes the handler with operation_canceled", "[observer][destructor]")
{
    GIVEN("a started observer that is destroyed without stop() draining")
    {
        mock_executor ex;
        observation_outcome done;

        {
            basic_observer<mock_policy> obs{ex, ignore_records()};
            obs.async_observe(record_into(done));
        }

        THEN("the completion handler fired with operation_canceled")
        {
            REQUIRE(done.fired);
            REQUIRE(done.ec == std::errc::operation_canceled);
        }
    }
}

SCENARIO("second async_observe completes with operation_in_progress", "[observer][one-shot]")
{
    GIVEN("an observer with an observation in flight")
    {
        mock_executor ex;
        basic_observer<mock_policy> obs{ex, ignore_records()};
        obs.async_observe();

        WHEN("async_observe() is called a second time")
        {
            observation_outcome done;
            obs.async_observe(record_into(done));
            ex.drain_posted();

            THEN("the second handler fires with operation_in_progress")
            {
                REQUIRE(done.fired);
                REQUIRE(done.ec == std::errc::operation_in_progress);
            }
        }
    }
}

SCENARIO("basic_observer with socket_options", "[observer][socket_options]")
{
    GIVEN("a socket_options with a specific interface address")
    {
        mock_executor ex;
        socket_options opts{.interface_address = "10.0.0.1", .multicast_ttl = uint8_t{64}};

        WHEN("basic_observer<mock_policy> is constructed with socket_options")
        {
            basic_observer<mock_policy> obs{ex, ignore_records(), opts};

            THEN("the socket stores the options")
            {
                REQUIRE(obs.socket().options().interface_address == "10.0.0.1");
                REQUIRE(obs.socket().options().multicast_ttl == 64);
            }
        }
    }
}
