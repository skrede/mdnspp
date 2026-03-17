#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("on_updated fires on TXT record change for live service", "[monitor][MON-04]")
{
    mock_executor ex;
    test_clock::reset();

    int updated_count{0};
    mdnspp::update_event last_event{};
    mdnspp::dns_type last_rtype{};

    mdnspp::monitor_options opts;
    opts.on_found = [](const mdnspp::resolved_service &) {};
    opts.on_updated = [&](const mdnspp::resolved_service &,
                          mdnspp::update_event ev,
                          mdnspp::dns_type rtype)
    {
        ++updated_count;
        last_event = ev;
        last_rtype = rtype;
    };

    test_monitor mon{ex, std::move(opts)};
    mon.watch("_http._tcp.local");
    ex.drain_posted();

    mon.async_start();
    ex.drain_posted();

    auto sender = default_sender();
    auto &sock  = mon.socket();

    // Bring service live
    auto pkt = make_ptr_packet("_http._tcp.local",
                               "TxtSvc._http._tcp.local",
                               "txtsvc.local",
                               "10.1.1.1");
    sock.inject_receive(sender, pkt);
    ex.drain_posted();

    // Now inject a TXT update for the live service
    auto txt_pkt = make_txt_packet("_http._tcp.local",
                                   "TxtSvc._http._tcp.local",
                                   "txtsvc.local",
                                   {{"version", "2"}});
    sock.inject_receive(sender, txt_pkt);
    ex.drain_posted();

    REQUIRE(updated_count >= 1);
    CHECK(last_event == mdnspp::update_event::added);
    CHECK(last_rtype == mdnspp::dns_type::txt);
}

TEST_CASE("on_updated fires when a new A record is added to live service", "[monitor][MON-04]")
{
    mock_executor ex;
    test_clock::reset();

    int updated_count{0};
    mdnspp::update_event last_event{};

    mdnspp::monitor_options opts;
    opts.on_found   = [](const mdnspp::resolved_service &) {};
    opts.on_updated = [&](const mdnspp::resolved_service &,
                          mdnspp::update_event ev,
                          mdnspp::dns_type)
    {
        ++updated_count;
        last_event = ev;
    };

    test_monitor mon{ex, std::move(opts)};
    mon.watch("_http._tcp.local");
    ex.drain_posted();

    mon.async_start();
    ex.drain_posted();

    auto sender = default_sender();
    auto &sock  = mon.socket();

    // Bring service live with initial address
    auto pkt = make_ptr_packet("_http._tcp.local",
                               "MultiAddr._http._tcp.local",
                               "multiaddr.local",
                               "10.2.2.2");
    sock.inject_receive(sender, pkt);
    ex.drain_posted();

    // Inject a second A record for the same hostname
    auto a_pkt = make_a_packet("_http._tcp.local",
                               "MultiAddr._http._tcp.local",
                               "multiaddr.local",
                               "10.2.2.3");
    sock.inject_receive(sender, a_pkt);
    ex.drain_posted();

    REQUIRE(updated_count >= 1);
    CHECK(last_event == mdnspp::update_event::added);
}

TEST_CASE("on_lost fires with timeout when SRV record expires", "[monitor][MON-04]")
{
    mock_executor ex;
    test_clock::reset();

    std::vector<mdnspp::loss_reason> lost_reasons;
    std::vector<std::string> lost_names;

    mdnspp::monitor_options opts;
    opts.on_found = [](const mdnspp::resolved_service &) {};
    opts.on_lost  = [&](const mdnspp::resolved_service &svc, mdnspp::loss_reason reason)
    {
        lost_names.push_back(svc.instance_name.str());
        lost_reasons.push_back(reason);
    };

    test_monitor mon{ex, std::move(opts)};
    mon.watch("_http._tcp.local");
    ex.drain_posted();

    mon.async_start();
    ex.drain_posted();

    auto sender = default_sender();
    auto &sock  = mon.socket();

    // Bring service live with TTL=1s (so it expires quickly)
    auto pkt = make_ptr_packet("_http._tcp.local",
                               "Expiring._http._tcp.local",
                               "expiring.local",
                               "172.16.0.1",
                               /*ttl=*/1);
    sock.inject_receive(sender, pkt);
    ex.drain_posted();

    // Advance clock past TTL so cache entries expire
    test_clock::advance(std::chrono::seconds(2));

    // Trigger expiry check (erase_expired is called when the scheduler fires)
    mon.tick_expired_for_test();
    ex.drain_posted();

    REQUIRE(lost_names.size() == 1);
    CHECK(lost_names[0] == "expiring._http._tcp.local.");
    REQUIRE(lost_reasons.size() == 1);
    CHECK(lost_reasons[0] == mdnspp::loss_reason::timeout);
}

TEST_CASE("on_lost fires with goodbye when SRV goodbye packet received", "[monitor][MON-04]")
{
    mock_executor ex;
    test_clock::reset();

    std::vector<mdnspp::loss_reason> lost_reasons;
    std::vector<std::string> lost_names;

    mdnspp::monitor_options opts;
    opts.on_found = [](const mdnspp::resolved_service &) {};
    opts.on_lost  = [&](const mdnspp::resolved_service &svc, mdnspp::loss_reason reason)
    {
        lost_names.push_back(svc.instance_name.str());
        lost_reasons.push_back(reason);
    };

    test_monitor mon{ex, std::move(opts)};
    mon.watch("_http._tcp.local");
    ex.drain_posted();

    mon.async_start();
    ex.drain_posted();

    auto sender = default_sender();
    auto &sock  = mon.socket();

    // Bring service live
    auto pkt = make_ptr_packet("_http._tcp.local",
                               "GoodbyeSvc._http._tcp.local",
                               "goodbyesvc.local",
                               "10.5.5.5");
    sock.inject_receive(sender, pkt);
    ex.drain_posted();

    // Inject goodbye SRV (TTL=0)
    auto goodbye_pkt = make_srv_packet("GoodbyeSvc._http._tcp.local",
                                       "goodbyesvc.local",
                                       8080,
                                       /*ttl=*/0);
    sock.inject_receive(sender, goodbye_pkt);
    ex.drain_posted();

    // Advance past the 1s RFC 6762 grace period and trigger expiry
    test_clock::advance(std::chrono::seconds(2));
    mon.tick_expired_for_test();
    ex.drain_posted();

    REQUIRE(lost_names.size() == 1);
    CHECK(lost_names[0] == "goodbyesvc._http._tcp.local.");
    REQUIRE(lost_reasons.size() == 1);
    CHECK(lost_reasons[0] == mdnspp::loss_reason::goodbye);
}
