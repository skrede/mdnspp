#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("async_start wires recv_loop; stop tears it down", "[monitor][MON-06]")
{
    mock_executor ex;
    test_clock::reset();

    bool done_called{false};
    test_monitor mon{ex};

    mon.async_start([&](std::error_code ec)
    {
        CHECK_FALSE(ec);
        done_called = true;
    });
    ex.drain_posted();

    // stop() posts teardown to executor
    mon.stop();
    ex.drain_posted();

    CHECK(done_called);
}

TEST_CASE("recv_loop: incoming packets are processed", "[monitor][MON-06]")
{
    mock_executor ex;
    test_clock::reset();

    bool found_called{false};
    mdnspp::monitor_options opts;
    opts.on_found = [&](const mdnspp::resolved_service &) { found_called = true; };

    test_monitor mon{ex, std::move(opts)};
    mon.watch("_http._tcp.local");
    ex.drain_posted();

    mon.async_start();
    ex.drain_posted();

    auto &sock = mon.socket();
    auto sender = default_sender();

    // Inject a packet that carries PTR+SRV+A for a watched service type
    auto pkt = make_ptr_packet("_http._tcp.local",
                               "LiveSvc._http._tcp.local",
                               "livesvc.local",
                               "192.168.0.99");
    sock.inject_receive(sender, pkt);
    ex.drain_posted();

    CHECK(found_called);
}

TEST_CASE("services(): empty before any discovery", "[monitor][MON-05]")
{
    mock_executor ex;
    test_clock::reset();

    test_monitor mon{ex};
    // No start, no watch, no packets -- snapshot must be empty
    CHECK(mon.services().empty());
}

TEST_CASE("services(): returns live service after resolution", "[monitor][MON-05]")
{
    mock_executor ex;
    test_clock::reset();

    test_monitor mon{ex};
    mon.watch("_http._tcp.local");
    ex.drain_posted();

    mon.async_start();
    ex.drain_posted();

    auto &sock = mon.socket();
    auto sender = default_sender();

    auto pkt = make_ptr_packet("_http._tcp.local",
                               "SnapSvc._http._tcp.local",
                               "snapsvc.local",
                               "10.20.30.40",
                               /*ttl=*/120);
    sock.inject_receive(sender, pkt);
    ex.drain_posted();

    auto snap = mon.services();
    REQUIRE(snap.size() == 1);
    CHECK(snap[0].instance_name == "SnapSvc._http._tcp.local");
    CHECK(snap[0].hostname      == "snapsvc.local");
    CHECK(snap[0].port          == 8080);
    REQUIRE_FALSE(snap[0].ipv4_addresses.empty());
    CHECK(snap[0].ipv4_addresses[0] == "10.20.30.40");
}

TEST_CASE("services(): wire_ttl and ttl_remaining populated from SRV cache entry",
          "[monitor][MON-05]")
{
    mock_executor ex;
    test_clock::reset();

    mdnspp::mdns_options mdns_opts;
    // No TTL refresh in this test -- just check snapshot TTL fields
    mdns_opts.ttl_refresh_thresholds = {};

    test_monitor mon{ex, mdnspp::monitor_options{}, mdnspp::socket_options{},
                     std::move(mdns_opts)};
    mon.watch("_http._tcp.local");
    ex.drain_posted();

    mon.async_start();
    ex.drain_posted();

    auto &sock = mon.socket();
    auto sender = default_sender();

    constexpr uint32_t wire_ttl = 120;
    auto pkt = make_ptr_packet("_http._tcp.local",
                               "TtlSvc._http._tcp.local",
                               "ttlsvc.local",
                               "1.2.3.4",
                               wire_ttl);
    sock.inject_receive(sender, pkt);
    ex.drain_posted();

    auto snap = mon.services();
    REQUIRE(snap.size() == 1);
    // wire_ttl must be populated from the SRV cache entry
    CHECK(snap[0].wire_ttl == wire_ttl);
    // ttl_remaining must be positive (full TTL at t=0)
    CHECK(snap[0].ttl_remaining > std::chrono::nanoseconds{0});
    // ttl_remaining should be close to wire_ttl seconds
    CHECK(snap[0].ttl_remaining <= std::chrono::seconds(wire_ttl));
}

TEST_CASE("services(): snapshot is consistent after service loss", "[monitor][MON-05]")
{
    mock_executor ex;
    test_clock::reset();

    test_monitor mon{ex};
    mon.watch("_http._tcp.local");
    ex.drain_posted();

    mon.async_start();
    ex.drain_posted();

    auto &sock = mon.socket();
    auto sender = default_sender();

    auto pkt = make_ptr_packet("_http._tcp.local",
                               "LostSvc._http._tcp.local",
                               "lostsvc.local",
                               "5.6.7.8",
                               /*ttl=*/1);
    sock.inject_receive(sender, pkt);
    ex.drain_posted();

    REQUIRE(mon.services().size() == 1);

    // Advance clock and expire
    test_clock::advance(std::chrono::seconds(2));
    mon.tick_expired_for_test();
    ex.drain_posted();

    CHECK(mon.services().empty());
}
