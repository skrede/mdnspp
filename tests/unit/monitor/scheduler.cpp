#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("scheduler: arm_scheduler arms the scheduler timer after async_start",
          "[monitor][scheduler]")
{
    mock_executor ex;
    test_clock::reset();

    mdnspp::mdns_options mdns_opts;
    mdns_opts.initial_interval = std::chrono::milliseconds{1000};
    mdns_opts.ttl_refresh_thresholds = {};

    mdnspp::monitor_options opts;
    opts.mode = mdnspp::monitor_mode::discover;

    test_monitor mon{ex, std::move(opts), mdnspp::socket_options{}, std::move(mdns_opts)};
    mon.watch("_http._tcp.local");
    ex.drain_posted();

    mon.async_start();
    ex.drain_posted();

    // After async_start + drain, the scheduler timer must have been armed
    auto &sched_timer = mon.scheduler_timer_for_test();
    CHECK(sched_timer.has_pending());
}

TEST_CASE("scheduler: discover mode first query after randomized 20-120ms delay",
          "[monitor][scheduler][MON-03]")
{
    mock_executor ex;
    test_clock::reset();

    mdnspp::mdns_options mdns_opts;
    mdns_opts.initial_interval = std::chrono::milliseconds{1000};
    mdns_opts.ttl_refresh_thresholds = {};

    mdnspp::monitor_options opts;
    opts.mode = mdnspp::monitor_mode::discover;

    test_monitor mon{ex, std::move(opts), mdnspp::socket_options{}, std::move(mdns_opts)};
    mon.watch("_http._tcp.local");
    ex.drain_posted();

    mon.async_start();
    ex.drain_posted();

    auto &sock = mon.socket();
    auto &sched_timer = mon.scheduler_timer_for_test();

    // No queries sent before timer fires
    CHECK(sock.sent_packets().empty());

    // First-query deadline is randomized in [20ms, 120ms] (RFC 6762 section 5.2)
    auto d0 = sched_timer.last_duration();
    CHECK(d0 >= std::chrono::milliseconds{20});
    CHECK(d0 <= std::chrono::milliseconds{120});

    // Advance to the watch deadline and fire the scheduler timer
    test_clock::advance(d0);
    sched_timer.fire();
    ex.drain_posted();

    // PTR query must have been sent for the watched type
    REQUIRE_FALSE(sock.sent_packets().empty());
}

TEST_CASE("scheduler: discover mode backoff doubles after each tick",
          "[monitor][scheduler][MON-03]")
{
    mock_executor ex;
    test_clock::reset();

    mdnspp::mdns_options mdns_opts;
    mdns_opts.initial_interval = std::chrono::milliseconds{1000};
    mdns_opts.max_interval     = std::chrono::milliseconds{60000};
    mdns_opts.backoff_multiplier = 2.0;
    mdns_opts.ttl_refresh_thresholds = {};

    mdnspp::monitor_options opts;
    opts.mode = mdnspp::monitor_mode::discover;

    test_monitor mon{ex, std::move(opts), mdnspp::socket_options{}, std::move(mdns_opts)};
    mon.watch("_http._tcp.local");
    ex.drain_posted();

    mon.async_start();
    ex.drain_posted();

    auto &sched_timer = mon.scheduler_timer_for_test();
    auto &sock = mon.socket();

    // Tick 1 (first-query delay): fires, sends query, re-arms at initial_interval
    test_clock::advance(sched_timer.last_duration());
    sched_timer.fire();
    ex.drain_posted();
    CHECK(sock.sent_packets().size() == 1);

    auto d1 = sched_timer.last_duration();
    CHECK(d1 == std::chrono::milliseconds{1000});

    // Tick 2: fires at the backoff deadline, sends query, re-arms at 2000ms
    test_clock::advance(d1);
    sched_timer.fire();
    ex.drain_posted();
    CHECK(sock.sent_packets().size() == 2);

    auto d2 = sched_timer.last_duration();
    CHECK(d2 == std::chrono::milliseconds{2000});

    // Tick 3: doubling continues to 4000ms
    test_clock::advance(d2);
    sched_timer.fire();
    ex.drain_posted();
    CHECK(sock.sent_packets().size() == 3);

    auto d3 = sched_timer.last_duration();
    CHECK(d3 == std::chrono::milliseconds{4000});
}

TEST_CASE("scheduler: a tick before the watch deadline does not query",
          "[monitor][scheduler][per-watch]")
{
    mock_executor ex;
    test_clock::reset();

    mdnspp::mdns_options mdns_opts;
    mdns_opts.initial_interval = std::chrono::milliseconds{1000};
    mdns_opts.ttl_refresh_thresholds = {};

    mdnspp::monitor_options opts;
    opts.mode = mdnspp::monitor_mode::discover;

    test_monitor mon{ex, std::move(opts), mdnspp::socket_options{}, std::move(mdns_opts)};
    mon.watch("_http._tcp.local");
    ex.drain_posted();

    mon.async_start();
    ex.drain_posted();

    auto &sock = mon.socket();
    auto &sched_timer = mon.scheduler_timer_for_test();

    // Fire WITHOUT advancing the clock: the watch deadline has not passed,
    // so no premature PTR query may be sent (RFC 6762 section 5.2).
    sched_timer.fire();
    ex.drain_posted();
    CHECK(sock.sent_packets().empty());

    // Once the deadline passes, the query fires.
    test_clock::advance(std::chrono::milliseconds{120});
    sched_timer.fire();
    ex.drain_posted();
    CHECK_FALSE(sock.sent_packets().empty());
}

TEST_CASE("scheduler: observe mode does NOT send PTR queries automatically",
          "[monitor][scheduler]")
{
    mock_executor ex;
    test_clock::reset();

    mdnspp::mdns_options mdns_opts;
    mdns_opts.ttl_refresh_thresholds = {};

    mdnspp::monitor_options opts;
    opts.mode = mdnspp::monitor_mode::observe;

    test_monitor mon{ex, std::move(opts), mdnspp::socket_options{}, std::move(mdns_opts)};
    mon.watch("_http._tcp.local");
    ex.drain_posted();

    mon.async_start();
    ex.drain_posted();

    auto &sock = mon.socket();
    auto &sched_timer = mon.scheduler_timer_for_test();

    // Fire multiple ticks -- still no queries should be sent
    sched_timer.fire();
    ex.drain_posted();
    CHECK(sock.sent_packets().empty());

    sched_timer.fire();
    ex.drain_posted();
    CHECK(sock.sent_packets().empty());
}

TEST_CASE("scheduler: erase_expired called on every tick (drives loss detection)",
          "[monitor][scheduler]")
{
    mock_executor ex;
    test_clock::reset();

    std::vector<std::string> lost_names;
    mdnspp::monitor_options opts;
    opts.mode     = mdnspp::monitor_mode::observe;
    opts.on_found = [](const mdnspp::resolved_service &) {};
    opts.on_lost  = [&](const mdnspp::resolved_service &svc, mdnspp::loss_reason)
    {
        lost_names.push_back(svc.instance_name.str());
    };

    mdnspp::mdns_options mdns_opts;
    mdns_opts.ttl_refresh_thresholds = {};

    test_monitor mon{ex, std::move(opts), mdnspp::socket_options{}, std::move(mdns_opts)};
    mon.watch("_http._tcp.local");
    ex.drain_posted();

    mon.async_start();
    ex.drain_posted();

    auto &sock        = mon.socket();
    auto &sched_timer = mon.scheduler_timer_for_test();
    auto sender       = default_sender();

    // Bring a service live with TTL=1s
    auto pkt = make_ptr_packet("_http._tcp.local",
                               "SchedExp._http._tcp.local",
                               "schedexp.local",
                               "7.8.9.0",
                               /*ttl=*/1);
    sock.inject_receive(sender, pkt);
    ex.drain_posted();

    REQUIRE(lost_names.empty());

    // Advance time and fire scheduler -- should call erase_expired internally
    test_clock::advance(std::chrono::seconds(2));
    sched_timer.fire();
    ex.drain_posted();

    REQUIRE(lost_names.size() == 1);
    CHECK(lost_names[0] == "SchedExp._http._tcp.local.");
}

TEST_CASE("ttl_refresh: refresh query sent at 80% threshold in ttl_refresh mode",
          "[monitor][ttl_refresh][MON-05]")
{
    mock_executor ex;
    test_clock::reset();

    mdnspp::mdns_options mdns_opts;
    // Single threshold at 80% for simplicity
    mdns_opts.ttl_refresh_thresholds = {0.80};
    mdns_opts.refresh_jitter_pct     = 0.0; // no jitter for deterministic test
    mdns_opts.initial_interval       = std::chrono::milliseconds{100000}; // large: no backoff queries

    mdnspp::monitor_options opts;
    opts.mode     = mdnspp::monitor_mode::ttl_refresh;
    opts.on_found = [](const mdnspp::resolved_service &) {};

    test_monitor mon{ex, std::move(opts), mdnspp::socket_options{}, std::move(mdns_opts)};
    mon.watch("_http._tcp.local");
    ex.drain_posted();

    mon.async_start();
    ex.drain_posted();

    auto &sock        = mon.socket();
    auto &sched_timer = mon.scheduler_timer_for_test();
    auto sender       = default_sender();

    // Bring a service live with wire_ttl=100s
    // 80% of 100s = 80s after insertion
    constexpr uint32_t wire_ttl = 100;
    auto pkt = make_ptr_packet("_http._tcp.local",
                               "RefreshSvc._http._tcp.local",
                               "refreshsvc.local",
                               "1.1.1.1",
                               wire_ttl);
    sock.inject_receive(sender, pkt);
    ex.drain_posted();

    // Clear any queries sent during setup
    sock.clear_sent();

    // Advance clock to just past 80% of wire_ttl (80s) and fire scheduler
    test_clock::advance(std::chrono::milliseconds(80001));
    sched_timer.fire();
    ex.drain_posted();

    // At least one refresh query should have been sent
    CHECK_FALSE(sock.sent_packets().empty());
}

TEST_CASE("query_service_type: sends PTR query immediately in any mode",
          "[monitor][MON-03][MON-05]")
{
    mock_executor ex;
    test_clock::reset();

    mdnspp::monitor_options opts;
    opts.mode = mdnspp::monitor_mode::observe; // observe: no auto queries

    mdnspp::mdns_options mdns_opts;
    mdns_opts.ttl_refresh_thresholds = {};

    test_monitor mon{ex, std::move(opts), mdnspp::socket_options{}, std::move(mdns_opts)};
    mon.async_start();
    ex.drain_posted();

    auto &sock = mon.socket();
    CHECK(sock.sent_packets().empty());

    mon.query_service_type("_http._tcp.local");
    ex.drain_posted();

    REQUIRE_FALSE(sock.sent_packets().empty());
}

TEST_CASE("query_service_instance: sends one multi-question SRV/TXT/A/AAAA query",
          "[monitor][MON-03][MON-05]")
{
    mock_executor ex;
    test_clock::reset();

    mdnspp::monitor_options opts;
    opts.mode = mdnspp::monitor_mode::observe;

    mdnspp::mdns_options mdns_opts;
    mdns_opts.ttl_refresh_thresholds = {};

    test_monitor mon{ex, std::move(opts), mdnspp::socket_options{}, std::move(mdns_opts)};
    mon.async_start();
    ex.drain_posted();

    auto &sock = mon.socket();
    CHECK(sock.sent_packets().empty());

    mon.query_service_instance("MyInstance._http._tcp.local");
    ex.drain_posted();

    // RFC 6762 section 5: ONE aggregated packet with four questions
    REQUIRE(sock.sent_packets().size() == 1);
    const auto &data = sock.sent_packets()[0].data;
    REQUIRE(data.size() >= 12);
    // QR=0 (query)
    CHECK((static_cast<uint8_t>(data[2]) & 0x80) == 0);
    // QDCOUNT == 4 (SRV, TXT, A, AAAA)
    CHECK(static_cast<uint8_t>(data[4]) == 0x00);
    CHECK(static_cast<uint8_t>(data[5]) == 0x04);
    // ANCOUNT == 0
    CHECK(static_cast<uint8_t>(data[6]) == 0x00);
    CHECK(static_cast<uint8_t>(data[7]) == 0x00);
}

TEST_CASE("per-watch scheduling: a TTL-refresh fire point does not trigger PTR queries",
          "[monitor][scheduler][per-watch][MON-05]")
{
    mock_executor ex;
    test_clock::reset();

    mdnspp::mdns_options mdns_opts;
    mdns_opts.ttl_refresh_thresholds = {0.80};
    mdns_opts.refresh_jitter_pct     = 0.0;
    mdns_opts.initial_interval       = std::chrono::milliseconds{200000};
    mdns_opts.max_interval           = std::chrono::milliseconds{400000};

    mdnspp::monitor_options opts;
    opts.mode     = mdnspp::monitor_mode::discover;
    opts.on_found = [](const mdnspp::resolved_service &) {};

    test_monitor mon{ex, std::move(opts), mdnspp::socket_options{}, std::move(mdns_opts)};
    mon.watch("_http._tcp.local");
    mon.watch("_ftp._tcp.local");
    ex.drain_posted();

    mon.async_start();
    ex.drain_posted();

    auto &sock        = mon.socket();
    auto &sched_timer = mon.scheduler_timer_for_test();
    auto sender       = default_sender();

    // Consume both watches' first queries (deadlines within 120ms)
    test_clock::advance(std::chrono::milliseconds{120});
    sched_timer.fire();
    ex.drain_posted();
    CHECK(sock.sent_packets().size() == 2);

    // Bring a service live with wire_ttl = 100s; its 80% refresh point (80s)
    // is far before both watches' next backoff deadlines (200s).
    auto pkt = make_ptr_packet("_http._tcp.local",
                               "Iso._http._tcp.local",
                               "iso.local",
                               "10.0.0.7",
                               /*ttl=*/100);
    sock.inject_receive(sender, pkt);
    ex.drain_posted();
    sock.clear_sent();

    // Advance to just past the refresh point (80 s after insertion) and fire
    // the shared timer.
    test_clock::advance(std::chrono::milliseconds{80001});
    sched_timer.fire();
    ex.drain_posted();

    // Exactly the instance refresh was sent -- no PTR query for either watch
    // (the old behaviour fired every watch on every tick).
    REQUIRE(sock.sent_packets().size() == 1);
    const auto &data = sock.sent_packets()[0].data;
    REQUIRE(data.size() >= 12);
    // The multi-question instance refresh has qdcount == 4; a PTR query has 1.
    CHECK(static_cast<uint8_t>(data[5]) == 0x04);
}

TEST_CASE("refresh schedules are pruned on exhaustion and SRV expiry",
          "[monitor][scheduler][pruning][MON-05]")
{
    mock_executor ex;
    test_clock::reset();

    mdnspp::mdns_options mdns_opts;
    mdns_opts.ttl_refresh_thresholds = {0.80};
    mdns_opts.refresh_jitter_pct     = 0.0;
    mdns_opts.initial_interval       = std::chrono::milliseconds{200000};
    mdns_opts.max_interval           = std::chrono::milliseconds{400000};

    mdnspp::monitor_options opts;
    opts.mode     = mdnspp::monitor_mode::ttl_refresh;
    opts.on_found = [](const mdnspp::resolved_service &) {};

    test_monitor mon{ex, std::move(opts), mdnspp::socket_options{}, std::move(mdns_opts)};
    mon.watch("_http._tcp.local");
    ex.drain_posted();

    mon.async_start();
    ex.drain_posted();

    auto &sock        = mon.socket();
    auto &sched_timer = mon.scheduler_timer_for_test();
    auto sender       = default_sender();

    SECTION("exhausted schedule is pruned after its last fire point")
    {
        auto pkt = make_ptr_packet("_http._tcp.local",
                                   "Prune._http._tcp.local",
                                   "prune.local",
                                   "10.0.0.8",
                                   /*ttl=*/100);
        sock.inject_receive(sender, pkt);
        ex.drain_posted();
        CHECK(mon.refresh_schedule_count_for_test() == 1);

        // Advance past the single 80% fire point -- but not past the 100s TTL
        test_clock::advance(std::chrono::milliseconds{80001});
        sched_timer.fire();
        ex.drain_posted();

        CHECK(mon.refresh_schedule_count_for_test() == 0);
    }

    SECTION("schedule is erased when the SRV record expires")
    {
        auto pkt = make_ptr_packet("_http._tcp.local",
                                   "Gone._http._tcp.local",
                                   "gone.local",
                                   "10.0.0.9",
                                   /*ttl=*/1);
        sock.inject_receive(sender, pkt);
        ex.drain_posted();
        CHECK(mon.refresh_schedule_count_for_test() == 1);

        test_clock::advance(std::chrono::seconds{2});
        mon.tick_expired_for_test();
        ex.drain_posted();

        CHECK(mon.refresh_schedule_count_for_test() == 0);
    }

    SECTION("schedule is erased on unwatch")
    {
        auto pkt = make_ptr_packet("_http._tcp.local",
                                   "Unwatched._http._tcp.local",
                                   "unwatched.local",
                                   "10.0.0.10",
                                   /*ttl=*/100);
        sock.inject_receive(sender, pkt);
        ex.drain_posted();
        CHECK(mon.refresh_schedule_count_for_test() == 1);

        mon.unwatch("_http._tcp.local");
        ex.drain_posted();

        CHECK(mon.refresh_schedule_count_for_test() == 0);
    }
}
