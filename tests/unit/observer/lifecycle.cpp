#include "helpers.h"

#include <system_error>

static observer_options stop_from_record(basic_observer<mock_policy> *const &obs_ptr, uint32_t &callback_count)
{
    return observer_options{.on_record = [&obs_ptr, &callback_count](const endpoint &, const mdns_record_variant &)
    {
        ++callback_count;
        if(obs_ptr)
            obs_ptr->stop();
    }};
}

SCENARIO("async_observe fires completion callback on stop", "[observer][async]")
{
    GIVEN("a fresh observer with no packets enqueued")
    {
        mock_executor ex;
        basic_observer<mock_policy> obs{ex, ignore_records()};

        WHEN("async_observe() is called with a completion callback")
        {
            observation_outcome done;
            obs.async_observe(record_into(done));

            AND_WHEN("stop() is called")
            {
                obs.stop();
                ex.drain_posted();

                THEN("the completion callback fires with operation_canceled")
                {
                    REQUIRE(done.fired);
                    REQUIRE(done.ec == std::errc::operation_canceled);
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
        basic_observer<mock_policy> obs{ex, ignore_records()};

        WHEN("async_observe() and then stop() are called twice")
        {
            obs.async_observe();

            THEN("the second stop() call does not crash or assert")
            {
                obs.stop();
                REQUIRE_NOTHROW(obs.stop());
            }
        }
    }
}

SCENARIO("async_observe completion handler fires exactly once on double stop", "[observer][stop-idempotent][completion]")
{
    GIVEN("an observer with a completion callback")
    {
        mock_executor ex;
        uint32_t completion_count = 0;
        basic_observer<mock_policy> obs{ex, ignore_records()};
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
        uint32_t callback_count = 0;
        basic_observer<mock_policy> obs{ex, count_records(callback_count)};

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
        uint32_t callback_count = 0;
        basic_observer<mock_policy> obs{ex, stop_from_record(obs_ptr, callback_count)};
        obs_ptr = &obs;
        obs.socket().enqueue(make_ptr_response("_http._tcp.local.", "Target._http._tcp.local."));

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

SCENARIO("observer skips malformed packets without crashing", "[observer][malformed-packet]")
{
    GIVEN("an observer with a truncated (malformed) packet enqueued")
    {
        mock_executor ex;
        // Five bytes, shorter than the 12-byte DNS header
        std::vector<std::byte> malformed = bytes({0x00, 0x00, 0x00, 0x00, 0x00});
        uint32_t callback_count = 0;
        basic_observer<mock_policy> obs{ex, count_records(callback_count)};
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
