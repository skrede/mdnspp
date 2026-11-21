#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <vector>
#include <utility>

namespace {

mdnspp::mdns_options one_second_interval()
{
    mdnspp::mdns_options opts = no_refresh_options();
    opts.initial_interval = std::chrono::milliseconds{1000};
    return opts;
}

}

TEST_CASE("scheduler: arm_scheduler arms the scheduler timer after async_start",
          "[monitor][scheduler]")
{
    monitor_fixture f{mode_options(mdnspp::monitor_mode::discover), one_second_interval()};
    f.watch_and_start({"_http._tcp.local"});

    CHECK(f.timer().has_pending());
}

TEST_CASE("scheduler: discover mode first query after randomized 20-120ms delay",
          "[monitor][scheduler]")
{
    monitor_fixture f{mode_options(mdnspp::monitor_mode::discover), one_second_interval()};
    f.watch_and_start({"_http._tcp.local"});
    CHECK(f.socket().sent_packets().empty());

    // First-query deadline is randomized in [20ms, 120ms] (RFC 6762 section 5.2)
    auto d0 = f.timer().last_duration();
    CHECK(d0 >= std::chrono::milliseconds{20});
    CHECK(d0 <= std::chrono::milliseconds{120});

    f.fire_after(d0);
    REQUIRE_FALSE(f.socket().sent_packets().empty());
}

TEST_CASE("scheduler: discover mode backoff doubles after each tick",
          "[monitor][scheduler]")
{
    mdnspp::mdns_options mdns_opts = one_second_interval();
    mdns_opts.max_interval = std::chrono::milliseconds{60000};
    mdns_opts.backoff_multiplier = 2.0;
    monitor_fixture f{mode_options(mdnspp::monitor_mode::discover), std::move(mdns_opts)};
    f.watch_and_start({"_http._tcp.local"});

    f.fire_after(f.timer().last_duration());
    CHECK(f.socket().sent_packets().size() == 1);
    CHECK(f.timer().last_duration() == std::chrono::milliseconds{1000});

    f.fire_after(f.timer().last_duration());
    CHECK(f.socket().sent_packets().size() == 2);
    CHECK(f.timer().last_duration() == std::chrono::milliseconds{2000});

    f.fire_after(f.timer().last_duration());
    CHECK(f.socket().sent_packets().size() == 3);
    CHECK(f.timer().last_duration() == std::chrono::milliseconds{4000});
}

TEST_CASE("scheduler: a tick before the watch deadline does not query",
          "[monitor][scheduler][per-watch]")
{
    monitor_fixture f{mode_options(mdnspp::monitor_mode::discover), one_second_interval()};
    f.watch_and_start({"_http._tcp.local"});

    // The clock has not reached the watch deadline, so no premature PTR query may be sent (RFC 6762 section 5.2).
    f.fire();
    CHECK(f.socket().sent_packets().empty());

    f.fire_after(std::chrono::milliseconds{120});
    CHECK_FALSE(f.socket().sent_packets().empty());
}

TEST_CASE("scheduler: observe mode does NOT send PTR queries automatically",
          "[monitor][scheduler]")
{
    monitor_fixture f{mode_options(mdnspp::monitor_mode::observe), no_refresh_options()};
    f.watch_and_start({"_http._tcp.local"});

    f.fire();
    CHECK(f.socket().sent_packets().empty());

    f.fire();
    CHECK(f.socket().sent_packets().empty());
}

TEST_CASE("scheduler: erase_expired called on every tick (drives loss detection)",
          "[monitor][scheduler]")
{
    std::vector<std::string> lost_names;
    mdnspp::monitor_options opts = mode_options(mdnspp::monitor_mode::observe);
    opts.on_found = [](const mdnspp::resolved_service &) {};
    opts.on_lost = [&](const mdnspp::resolved_service &svc, mdnspp::loss_reason)
    {
        lost_names.push_back(svc.instance_name.str());
    };
    monitor_fixture f{std::move(opts), no_refresh_options()};
    f.watch_and_start({"_http._tcp.local"});

    f.inject(make_ptr_packet("_http._tcp.local", "SchedExp._http._tcp.local", "schedexp.local", "7.8.9.0", /*ttl=*/1));
    REQUIRE(lost_names.empty());

    f.fire_after(std::chrono::seconds(2));
    REQUIRE(lost_names.size() == 1);
    CHECK(lost_names[0] == "SchedExp._http._tcp.local.");
}
