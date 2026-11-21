#ifndef HPP_GUARD_MDNSPP_MONITOR_FIXTURE_H
#define HPP_GUARD_MDNSPP_MONITOR_FIXTURE_H

#include "helpers.h"

#include "mdnspp/mdns_options.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/monitor_options.h"

#include <chrono>
#include <vector>
#include <cstddef>
#include <utility>
#include <string_view>
#include <initializer_list>

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

struct monitor_fixture
{
    // The clock is reset after construction because the monitor first reads it on watch or start.
    monitor_fixture(mdnspp::monitor_options opts, mdnspp::mdns_options mdns_opts)
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

    mock_executor ex;
    test_monitor mon;
};

#endif
