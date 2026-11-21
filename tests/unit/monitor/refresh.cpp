#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>

namespace {

mdnspp::monitor_options found_options(mdnspp::monitor_mode mode)
{
    mdnspp::monitor_options opts = mode_options(mode);
    opts.on_found = [](const mdnspp::resolved_service &) {};
    return opts;
}

mdnspp::mdns_options refresh_at_80(std::chrono::milliseconds initial_interval)
{
    mdnspp::mdns_options opts;
    opts.ttl_refresh_thresholds = {0.80};
    opts.refresh_jitter_pct = 0.0; // deterministic fire points
    opts.initial_interval = initial_interval;
    return opts;
}

mdnspp::mdns_options slow_backoff_refresh()
{
    mdnspp::mdns_options opts = refresh_at_80(std::chrono::milliseconds{200000});
    opts.max_interval = std::chrono::milliseconds{400000};
    return opts;
}

void schedule_erase_sections(monitor_fixture &f)
{
    SECTION("schedule is erased when the SRV record expires")
    {
        f.inject(make_ptr_packet("_http._tcp.local", "Gone._http._tcp.local", "gone.local", "10.0.0.9", /*ttl=*/1));
        CHECK(f.mon.refresh_schedule_count_for_test() == 1);

        test_clock::advance(std::chrono::seconds{2});
        f.mon.tick_expired_for_test();
        f.ex.drain_posted();
        CHECK(f.mon.refresh_schedule_count_for_test() == 0);
    }

    SECTION("schedule is erased on unwatch")
    {
        f.inject(make_ptr_packet("_http._tcp.local", "Unwatched._http._tcp.local", "unwatched.local", "10.0.0.10",
                                 /*ttl=*/100));
        CHECK(f.mon.refresh_schedule_count_for_test() == 1);

        f.mon.unwatch("_http._tcp.local");
        f.ex.drain_posted();
        CHECK(f.mon.refresh_schedule_count_for_test() == 0);
    }
}

}

TEST_CASE("ttl_refresh: refresh query sent at 80% threshold in ttl_refresh mode",
          "[monitor][ttl_refresh][MON-05]")
{
    // The 100 s initial interval keeps backoff queries out of the refresh window.
    monitor_fixture f{found_options(mdnspp::monitor_mode::ttl_refresh),
                      refresh_at_80(std::chrono::milliseconds{100000})};
    f.watch_and_start({"_http._tcp.local"});

    constexpr uint32_t wire_ttl = 100;
    f.inject(make_ptr_packet("_http._tcp.local", "RefreshSvc._http._tcp.local", "refreshsvc.local", "1.1.1.1",
                             wire_ttl));
    f.socket().clear_sent();

    f.fire_after(std::chrono::milliseconds(80001));
    CHECK_FALSE(f.socket().sent_packets().empty());
}

TEST_CASE("per-watch scheduling: a TTL-refresh fire point does not trigger PTR queries",
          "[monitor][scheduler][per-watch][MON-05]")
{
    monitor_fixture f{found_options(mdnspp::monitor_mode::discover), slow_backoff_refresh()};
    f.watch_and_start({"_http._tcp.local", "_ftp._tcp.local"});
    f.fire_after(std::chrono::milliseconds{120});
    CHECK(f.socket().sent_packets().size() == 2);

    // The 80% refresh point of a 100 s TTL (80 s) lies far before both watches' next backoff deadlines (200 s).
    f.inject(make_ptr_packet("_http._tcp.local", "Iso._http._tcp.local", "iso.local", "10.0.0.7", /*ttl=*/100));
    f.socket().clear_sent();
    f.fire_after(std::chrono::milliseconds{80001});

    REQUIRE(f.socket().sent_packets().size() == 1);
    const auto &data = f.socket().sent_packets()[0].data;
    REQUIRE(data.size() >= 12);
    // The multi-question instance refresh has qdcount == 4; a PTR query has 1.
    CHECK(static_cast<uint8_t>(data[5]) == 0x04);
}

TEST_CASE("refresh schedules are pruned on exhaustion and SRV expiry",
          "[monitor][scheduler][pruning][MON-05]")
{
    monitor_fixture f{found_options(mdnspp::monitor_mode::ttl_refresh), slow_backoff_refresh()};
    f.watch_and_start({"_http._tcp.local"});

    SECTION("exhausted schedule is pruned after its last fire point")
    {
        f.inject(make_ptr_packet("_http._tcp.local", "Prune._http._tcp.local", "prune.local", "10.0.0.8", /*ttl=*/100));
        CHECK(f.mon.refresh_schedule_count_for_test() == 1);

        // Past the single 80% fire point but not past the 100 s TTL.
        f.fire_after(std::chrono::milliseconds{80001});
        CHECK(f.mon.refresh_schedule_count_for_test() == 0);
    }

    schedule_erase_sections(f);
}
