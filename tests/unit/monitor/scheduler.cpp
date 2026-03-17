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

TEST_CASE("scheduler: discover mode sends PTR query on first tick",
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

    // Fire the scheduler timer
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

    // Tick 1: fires, sends query, re-arms at 2000ms (next backoff after initial 1000ms)
    sched_timer.fire();
    ex.drain_posted();
    CHECK(sock.sent_packets().size() == 1);

    auto d1 = sched_timer.last_duration();
    CHECK(d1 == std::chrono::milliseconds{2000});

    // Tick 2: fires, sends query, re-arms at 4000ms
    sched_timer.fire();
    ex.drain_posted();
    CHECK(sock.sent_packets().size() == 2);

    auto d2 = sched_timer.last_duration();
    CHECK(d2 == std::chrono::milliseconds{4000});
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
    CHECK(lost_names[0] == "schedexp._http._tcp.local.");
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

TEST_CASE("query_service_instance: sends SRV+A+AAAA queries in any mode",
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

    // Must send SRV + A + AAAA queries (3 packets)
    CHECK(sock.sent_packets().size() >= 3);
}
