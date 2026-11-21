#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <system_error>

TEST_CASE("async_start wires recv_loop; stop tears it down", "[monitor]")
{
    bool done_called{false};
    monitor_fixture f;

    f.mon.async_start([&](std::error_code ec)
    {
        CHECK_FALSE(ec);
        done_called = true;
    });
    f.ex.drain_posted();

    f.mon.stop();
    f.ex.drain_posted();

    CHECK(done_called);
}

TEST_CASE("recv_loop: incoming packets are processed", "[monitor]")
{
    bool found_called{false};
    monitor_fixture f{flag_found(found_called)};
    f.watch_and_start({"_http._tcp.local"});

    f.inject(make_ptr_packet("_http._tcp.local", "LiveSvc._http._tcp.local", "livesvc.local", "192.168.0.99"));

    CHECK(found_called);
}

TEST_CASE("services(): empty before any discovery", "[monitor]")
{
    monitor_fixture f;
    CHECK(f.mon.services().empty());
}

TEST_CASE("services(): returns live service after resolution", "[monitor]")
{
    monitor_fixture f;
    f.watch_and_start({"_http._tcp.local"});
    f.inject(make_ptr_packet("_http._tcp.local", "SnapSvc._http._tcp.local", "snapsvc.local", "10.20.30.40", 120));

    auto snap = f.mon.services();
    REQUIRE(snap.size() == 1);
    CHECK(snap[0].instance_name == "SnapSvc._http._tcp.local");
    CHECK(snap[0].hostname      == "snapsvc.local");
    CHECK(snap[0].port          == 8080);
    REQUIRE_FALSE(snap[0].ipv4_addresses.empty());
    CHECK(snap[0].ipv4_addresses[0] == "10.20.30.40");
}

TEST_CASE("services(): wire_ttl and ttl_remaining populated from SRV cache entry",
          "[monitor]")
{
    monitor_fixture f{mdnspp::monitor_options{}, no_refresh_options()};
    f.watch_and_start({"_http._tcp.local"});
    constexpr uint32_t wire_ttl = 120;
    f.inject(make_ptr_packet("_http._tcp.local", "TtlSvc._http._tcp.local", "ttlsvc.local", "1.2.3.4", wire_ttl));

    auto snap = f.mon.services();
    REQUIRE(snap.size() == 1);
    CHECK(snap[0].wire_ttl == wire_ttl);
    CHECK(snap[0].ttl_remaining > std::chrono::nanoseconds{0});
    CHECK(snap[0].ttl_remaining <= std::chrono::seconds(wire_ttl));
}

TEST_CASE("services(): snapshot is consistent after service loss", "[monitor]")
{
    monitor_fixture f;
    f.watch_and_start({"_http._tcp.local"});
    f.inject(make_ptr_packet("_http._tcp.local", "LostSvc._http._tcp.local", "lostsvc.local", "5.6.7.8", /*ttl=*/1));
    REQUIRE(f.mon.services().size() == 1);

    f.tick_expired_after(std::chrono::seconds(2));

    CHECK(f.mon.services().empty());
}
