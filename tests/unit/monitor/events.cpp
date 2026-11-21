#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>

namespace {

struct update_log
{
    int32_t count;
    mdnspp::update_event last_event;
    mdnspp::dns_type last_rtype;
};

mdnspp::monitor_options update_options(update_log &log)
{
    mdnspp::monitor_options opts;
    opts.on_found = [](const mdnspp::resolved_service &) {};
    opts.on_updated = [&log](const mdnspp::resolved_service &, mdnspp::update_event ev, mdnspp::dns_type rtype)
    {
        ++log.count;
        log.last_event = ev;
        log.last_rtype = rtype;
    };
    return opts;
}

}

TEST_CASE("on_updated fires on TXT record change for live service", "[monitor]")
{
    update_log updated{};
    monitor_fixture f{update_options(updated)};
    f.watch_and_start({"_http._tcp.local"});
    f.inject(make_ptr_packet("_http._tcp.local", "TxtSvc._http._tcp.local", "txtsvc.local", "10.1.1.1"));

    f.inject(make_txt_packet("_http._tcp.local", "TxtSvc._http._tcp.local", "txtsvc.local", {{"version", "2"}}));

    REQUIRE(updated.count >= 1);
    CHECK(updated.last_event == mdnspp::update_event::added);
    CHECK(updated.last_rtype == mdnspp::dns_type::txt);
}

TEST_CASE("on_updated fires when a new A record is added to live service", "[monitor]")
{
    update_log updated{};
    monitor_fixture f{update_options(updated)};
    f.watch_and_start({"_http._tcp.local"});
    f.inject(make_ptr_packet("_http._tcp.local", "MultiAddr._http._tcp.local", "multiaddr.local", "10.2.2.2"));

    f.inject(make_a_packet("_http._tcp.local", "MultiAddr._http._tcp.local", "multiaddr.local", "10.2.2.3"));

    REQUIRE(updated.count >= 1);
    CHECK(updated.last_event == mdnspp::update_event::added);
}

TEST_CASE("on_lost fires with timeout when SRV record expires", "[monitor]")
{
    loss_log lost{};
    monitor_fixture f{loss_options(lost)};
    f.watch_and_start({"_http._tcp.local"});
    f.inject(make_ptr_packet("_http._tcp.local", "Expiring._http._tcp.local", "expiring.local", "172.16.0.1", 1));

    f.tick_expired_after(std::chrono::seconds(2));

    check_single_loss(lost, "Expiring._http._tcp.local.", mdnspp::loss_reason::timeout);
}

TEST_CASE("on_lost fires with goodbye when SRV goodbye packet received", "[monitor]")
{
    loss_log lost{};
    monitor_fixture f{loss_options(lost)};
    f.watch_and_start({"_http._tcp.local"});
    f.inject(make_ptr_packet("_http._tcp.local", "GoodbyeSvc._http._tcp.local", "goodbyesvc.local", "10.5.5.5"));

    f.inject(make_srv_packet("GoodbyeSvc._http._tcp.local", "goodbyesvc.local", 8080, /*ttl=*/0));
    // Past the 1 s goodbye grace period of RFC 6762 section 10.1.
    f.tick_expired_after(std::chrono::seconds(2));

    check_single_loss(lost, "GoodbyeSvc._http._tcp.local.", mdnspp::loss_reason::goodbye);
}
