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
