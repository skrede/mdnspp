#include "helpers.h"

#include <type_traits>
#include <system_error>

SCENARIO("async_observe fires completion callback on stop", "[observer][async]")
{
    GIVEN("a fresh observer with no packets enqueued")
    {
        mock_executor ex;

        basic_observer<mock_policy> obs{
            ex,
            observer_options{.on_record = [](const endpoint &, const mdns_record_variant &)
            {
            }}
        };

        WHEN("async_observe() is called with a completion callback")
        {
            std::error_code received_ec;
            bool callback_fired = false;

            obs.async_observe([&](std::error_code ec)
            {
                callback_fired = true;
                received_ec = ec;
            });

            AND_WHEN("stop() is called")
            {
                obs.stop();
                ex.drain_posted();

                THEN("the completion callback fires with operation_canceled")
                {
                    REQUIRE(callback_fired);
                    REQUIRE(received_ec == std::errc::operation_canceled);
                }
            }
        }
    }
}

SCENARIO("stop() is idempotent — second call is a no-op", "[observer][stop-idempotent]")
{
    GIVEN("a started observer with no packets enqueued")
    {
        mock_executor ex;

        basic_observer<mock_policy> obs{
            ex,
            observer_options{.on_record = [](const endpoint &, const mdns_record_variant &)
            {
            }}
        };

        WHEN("async_observe() and then stop() are called twice")
        {
            obs.async_observe();

            THEN("the second stop() call does not crash or assert")
            {
                obs.stop();
                REQUIRE_NOTHROW(obs.stop()); // second call must be no-op
            }
        }
    }
}

SCENARIO("async_observe completion handler fires exactly once on double stop", "[observer][stop-idempotent][completion]")
{
    GIVEN("an observer with a completion callback")
    {
        mock_executor ex;
        int completion_count = 0;

        basic_observer<mock_policy> obs{
            ex,
            observer_options{.on_record = [](const endpoint &, const mdns_record_variant &)
            {
            }}
        };
        obs.async_observe([&](std::error_code) { ++completion_count; });

        WHEN("stop() is called twice")
        {
            obs.stop();
            obs.stop();
            ex.drain_posted();

            THEN("the completion callback fires exactly once")
            {
                REQUIRE(completion_count == 1);
            }
        }
    }
}

SCENARIO("observer can be created, started, and stopped without any packet delivery", "[observer][lifecycle]")
{
    GIVEN("a fresh observer with no packets enqueued")
    {
        mock_executor ex;
        int callback_count = 0;

        basic_observer<mock_policy> obs{
            ex,
            observer_options{.on_record = [&](const endpoint &, const mdns_record_variant &) { ++callback_count; }}
        };

        WHEN("async_observe() and stop() are called on the empty observer")
        {
            obs.async_observe();
            obs.stop();

            THEN("the record callback is never invoked")
            {
                REQUIRE(callback_count == 0);
            }
        }
    }
}

SCENARIO("stop() called from within the record callback does not deadlock", "[observer][callback-safe-stop]")
{
    GIVEN("an observer with one packet enqueued")
    {
        mock_executor ex;

        basic_observer<mock_policy> *obs_ptr = nullptr;
        int callback_count = 0;

        basic_observer<mock_policy> obs{
            ex,
            observer_options{.on_record = [&](const endpoint &, const mdns_record_variant &)
            {
                ++callback_count;
                // Call stop() from within the callback -- must not deadlock
                if(obs_ptr)
                    obs_ptr->stop();
            }}
        };
        obs_ptr = &obs;

        obs.socket().enqueue(
            make_ptr_response("_http._tcp.local.", "Target._http._tcp.local."));

        WHEN("async_observe() is called (callback will call stop() inside itself)")
        {
            THEN("async_observe() returns without deadlocking and stop flag is set")
            {
                REQUIRE_NOTHROW(obs.async_observe());
                REQUIRE(callback_count >= 1);
            }
        }
    }
}

SCENARIO("observer non-throwing constructor sets ec on success", "[observer][create][non-throwing]")
{
    GIVEN("a mock_executor and an error_code")
    {
        mock_executor ex;
        std::error_code ec;

        WHEN("basic_observer<mock_policy> is constructed with the ec overload")
        {
            basic_observer<mock_policy> obs{
                ex,
                observer_options{.on_record = [](const endpoint &, const mdns_record_variant &)
                {
                }},
                {},
                {},
                ec
            };

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
        std::error_code received_ec;
        bool callback_fired = false;

        {
            basic_observer<mock_policy> obs{
                ex,
                observer_options{.on_record = [](const endpoint &, const mdns_record_variant &)
                {
                }}
            };
            obs.async_observe([&](std::error_code ec)
            {
                callback_fired = true;
                received_ec = ec;
            });
        } // destroyed with the observation pending

        THEN("the completion handler fired with operation_canceled")
        {
            REQUIRE(callback_fired);
            REQUIRE(received_ec == std::errc::operation_canceled);
        }
    }
}

SCENARIO("second async_observe completes with operation_in_progress", "[observer][one-shot]")
{
    GIVEN("an observer with an observation in flight")
    {
        mock_executor ex;
        basic_observer<mock_policy> obs{
            ex,
            observer_options{.on_record = [](const endpoint &, const mdns_record_variant &)
            {
            }}
        };
        obs.async_observe();

        WHEN("async_observe() is called a second time")
        {
            std::error_code received_ec;
            bool callback_fired = false;

            obs.async_observe([&](std::error_code ec)
            {
                callback_fired = true;
                received_ec = ec;
            });
            ex.drain_posted();

            THEN("the second handler fires with operation_in_progress")
            {
                REQUIRE(callback_fired);
                REQUIRE(received_ec == std::errc::operation_in_progress);
            }
        }
    }
}

SCENARIO("observer skips malformed packets without crashing", "[observer][malformed-packet]")
{
    GIVEN("an observer with a truncated (malformed) packet enqueued")
    {
        mock_executor ex;

        // Only 5 bytes — too short to be a valid DNS header (needs 12)
        std::vector<std::byte> malformed = bytes({0x00, 0x00, 0x00, 0x00, 0x00});

        int callback_count = 0;

        basic_observer<mock_policy> obs{
            ex,
            observer_options{.on_record = [&](const endpoint &, const mdns_record_variant &) { ++callback_count; }}
        };
        obs.socket().enqueue(malformed);

        WHEN("async_observe() is called with the malformed packet")
        {
            THEN("no crash occurs and no records are delivered")
            {
                REQUIRE_NOTHROW(obs.async_observe());
                REQUIRE(callback_count == 0);
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
            basic_observer<mock_policy> obs{
                ex,
                observer_options{.on_record = [](const endpoint &, const mdns_record_variant &) {}},
                opts
            };

            THEN("the socket stores the options")
            {
                REQUIRE(obs.socket().options().interface_address == "10.0.0.1");
                REQUIRE(obs.socket().options().multicast_ttl == 64);
            }
        }
    }
}
