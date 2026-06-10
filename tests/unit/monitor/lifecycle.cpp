#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("basic_service_monitor: throwing constructor", "[monitor]")
{
    mock_executor ex;
    test_monitor mon{ex};
    // If construction reaches here without throwing, the test passes.
    // The monitor starts stopped (no async_start has been called).
}

TEST_CASE("basic_service_monitor: non-throwing constructor", "[monitor]")
{
    mock_executor ex;
    std::error_code ec;
    test_monitor mon{ex, mdnspp::monitor_options{}, mdnspp::socket_options{},
                     mdnspp::mdns_options{}, mdnspp::cache_options{}, ec};
    REQUIRE_FALSE(ec);
}

TEST_CASE("monitor_options: default construction", "[monitor]")
{
    mdnspp::monitor_options opts;
    CHECK(opts.mode == mdnspp::monitor_mode::discover);
    CHECK_FALSE(opts.on_found);
    CHECK_FALSE(opts.on_updated);
    CHECK_FALSE(opts.on_lost);
}

TEST_CASE("monitor_options: designated initializers", "[monitor]")
{
    mdnspp::monitor_options opts{.mode = mdnspp::monitor_mode::observe};
    CHECK(opts.mode == mdnspp::monitor_mode::observe);
}

TEST_CASE("resolved_service: TTL fields default to zero", "[monitor]")
{
    mdnspp::resolved_service svc;
    CHECK(svc.ttl_remaining == std::chrono::nanoseconds{0});
    CHECK(svc.wire_ttl == 0u);
}

TEST_CASE("basic_service_monitor: second async_start completes with operation_in_progress", "[monitor][one-shot]")
{
    mock_executor ex;
    test_clock::reset();

    test_monitor mon{ex};
    mon.async_start();
    ex.drain_posted();

    std::error_code received_ec;
    bool callback_fired = false;

    mon.async_start([&](std::error_code ec)
    {
        callback_fired = true;
        received_ec = ec;
    });
    ex.drain_posted();

    REQUIRE(callback_fired);
    CHECK(received_ec == std::errc::operation_in_progress);
}

TEST_CASE("basic_service_monitor: async_start after stop completes with invalid_argument", "[monitor][one-shot]")
{
    mock_executor ex;
    test_clock::reset();

    test_monitor mon{ex};
    mon.stop();
    ex.drain_posted();

    std::error_code received_ec;
    bool callback_fired = false;

    mon.async_start([&](std::error_code ec)
    {
        callback_fired = true;
        received_ec = ec;
    });
    ex.drain_posted();

    REQUIRE(callback_fired);
    CHECK(received_ec == std::errc::invalid_argument);
}

TEST_CASE("basic_service_monitor: constructor rejects invalid options", "[monitor][validate]")
{
    mock_executor ex;

    SECTION("backoff_multiplier below 1.0")
    {
        mdnspp::mdns_options bad;
        bad.backoff_multiplier = 0.5;

        std::error_code ec;
        test_monitor mon{ex, mdnspp::monitor_options{}, mdnspp::socket_options{},
                         std::move(bad), mdnspp::cache_options{}, ec};
        CHECK(ec == std::errc::invalid_argument);
    }

    SECTION("ttl refresh threshold outside (0,1)")
    {
        mdnspp::mdns_options bad;
        bad.ttl_refresh_thresholds = {0.8, 1.5};

        std::error_code ec;
        test_monitor mon{ex, mdnspp::monitor_options{}, mdnspp::socket_options{},
                         std::move(bad), mdnspp::cache_options{}, ec};
        CHECK(ec == std::errc::invalid_argument);
    }

    SECTION("non-positive goodbye_grace")
    {
        mdnspp::cache_options bad;
        bad.goodbye_grace = std::chrono::seconds{0};

        std::error_code ec;
        test_monitor mon{ex, mdnspp::monitor_options{}, mdnspp::socket_options{},
                         mdnspp::mdns_options{}, std::move(bad), ec};
        CHECK(ec == std::errc::invalid_argument);
    }

    SECTION("throwing constructor throws system_error")
    {
        mdnspp::mdns_options bad;
        bad.backoff_multiplier = 0.0;

        REQUIRE_THROWS_AS((test_monitor{ex, mdnspp::monitor_options{}, mdnspp::socket_options{},
                                        std::move(bad)}),
                          std::system_error);
    }
}

TEST_CASE("basic_service_monitor: destruction completes a pending handler with operation_canceled",
          "[monitor][destructor]")
{
    mock_executor ex;
    test_clock::reset();

    std::error_code received_ec;
    bool callback_fired = false;

    {
        test_monitor mon{ex};
        mon.async_start([&](std::error_code ec)
        {
            callback_fired = true;
            received_ec = ec;
        });
        ex.drain_posted();
    } // destroyed without draining a stop()

    REQUIRE(callback_fired);
    CHECK(received_ec == std::errc::operation_canceled);
}
