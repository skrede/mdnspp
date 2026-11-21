#ifndef HPP_GUARD_MDNSPP_MONITOR_FIXTURE_H
#define HPP_GUARD_MDNSPP_MONITOR_FIXTURE_H

#include "helpers.h"

#include "mdnspp/mdns_options.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/monitor_options.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <vector>
#include <cstddef>
#include <utility>
#include <string_view>
#include <initializer_list>

struct loss_log
{
    std::vector<std::string> names;
    std::vector<mdnspp::loss_reason> reasons;
};

inline mdnspp::monitor_options mode_options(mdnspp::monitor_mode mode)
{
    mdnspp::monitor_options opts;
    opts.mode = mode;
    return opts;
}

inline mdnspp::mdns_options no_refresh_options()
{
    mdnspp::mdns_options opts;
    opts.ttl_refresh_thresholds = {};
    return opts;
}

inline mdnspp::monitor_options flag_found(bool &found)
{
    mdnspp::monitor_options opts;
    opts.on_found = [&found](const mdnspp::resolved_service &) { found = true; };
    return opts;
}

inline mdnspp::monitor_options loss_options(loss_log &log)
{
    mdnspp::monitor_options opts;
    opts.on_found = [](const mdnspp::resolved_service &) {};
    opts.on_lost = [&log](const mdnspp::resolved_service &svc, mdnspp::loss_reason reason)
    {
        log.names.push_back(svc.instance_name.str());
        log.reasons.push_back(reason);
    };
    return opts;
}

inline void check_single_loss(const loss_log &log, std::string_view name, mdnspp::loss_reason reason)
{
    REQUIRE(log.names.size() == 1);
    CHECK(log.names[0] == name);
    REQUIRE(log.reasons.size() == 1);
    CHECK(log.reasons[0] == reason);
}

struct monitor_fixture
{
    // The clock is reset after construction because the monitor first reads it on watch or start.
    explicit monitor_fixture(mdnspp::monitor_options opts = {}, mdnspp::mdns_options mdns_opts = {})
        : ex{}
        , mon{ex, std::move(opts), mdnspp::socket_options{}, std::move(mdns_opts)}
    {
        test_clock::reset();
    }

    test_monitor::socket_type &socket()
    {
        return mon.socket();
    }

    test_monitor::timer_type &timer()
    {
        return mon.scheduler_timer_for_test();
    }

    void start()
    {
        mon.async_start();
        ex.drain_posted();
    }

    void watch_and_start(std::initializer_list<std::string_view> service_types)
    {
        for(std::string_view type : service_types)
            mon.watch(type);
        ex.drain_posted();
        start();
    }

    void inject(std::vector<std::byte> packet)
    {
        socket().inject_receive(default_sender(), std::move(packet));
        ex.drain_posted();
    }

    void fire()
    {
        timer().fire();
        ex.drain_posted();
    }

    void fire_after(std::chrono::milliseconds delay)
    {
        test_clock::advance(delay);
        fire();
    }

    void tick_expired_after(std::chrono::milliseconds delay)
    {
        test_clock::advance(delay);
        mon.tick_expired_for_test();
        ex.drain_posted();
    }

    mock_executor ex;
    test_monitor mon;
};

#endif
