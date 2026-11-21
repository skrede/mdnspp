#ifndef HPP_GUARD_MDNSPP_INPROC_BUS_HELPERS_H
#define HPP_GUARD_MDNSPP_INPROC_BUS_HELPERS_H

#include "mdnspp/inproc/inproc_harness.h"

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/service_info.h"
#include "mdnspp/cache_options.h"
#include "mdnspp/basic_observer.h"
#include "mdnspp/monitor_options.h"
#include "mdnspp/observer_options.h"
#include "mdnspp/resolved_service.h"
#include "mdnspp/basic_service_server.h"
#include "mdnspp/basic_service_monitor.h"

#include "mdnspp/testing/test_clock.h"

#include <chrono>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <variant>
#include <algorithm>
#include <string_view>

using namespace mdnspp;
using namespace std::chrono_literals;
using mdnspp::inproc::inproc_harness;
using mdnspp::testing::test_clock;

using inproc_server = basic_service_server<inproc_test_policy>;
using inproc_monitor = basic_service_monitor<inproc_test_policy, test_clock>;
using inproc_observer = basic_observer<inproc_test_policy>;

inline service_info make_service(std::string_view name, std::string_view type, std::string_view host, uint16_t port,
                                 std::string_view ipv4 = "192.168.1.1")
{
    service_info info;
    info.service_name = std::string(name);
    info.service_type = std::string(type);
    info.hostname = std::string(host);
    info.port = port;
    info.address_ipv4 = std::string(ipv4);
    return info;
}

// Capping both intervals at 200 ms keeps erase_expired() running often enough within the advance window.
inline mdns_options fast_scheduler_opts()
{
    mdns_options opts;
    opts.initial_interval = 200ms;
    opts.max_interval = 200ms;
    return opts;
}

inline monitor_options discover_opts()
{
    monitor_options opts;
    opts.mode = monitor_mode::discover;
    opts.on_found = [](const resolved_service &) {};
    return opts;
}

inline observer_options record_sink(std::vector<mdns_record_variant> &records)
{
    observer_options opts;
    opts.on_record = [&records](const endpoint &, const mdns_record_variant &rec) { records.push_back(rec); };
    return opts;
}

inline observer_options record_counter(std::size_t &count)
{
    observer_options opts;
    opts.on_record = [&count](const endpoint &, const mdns_record_variant &) { ++count; };
    return opts;
}

template <typename T>
bool holds_record(const std::vector<mdns_record_variant> &records)
{
    return std::ranges::any_of(records, [](const mdns_record_variant &rec) { return std::holds_alternative<T>(rec); });
}

// The probe 2, probe 3, conflict window and second announcement steps of inproc_harness::advance_to_live with
// default service_options, for peers the test holds no server object of.
inline void finish_ceremony(inproc_harness &h)
{
    h.advance(250ms);
    h.advance(250ms);
    h.advance(250ms);
    h.advance(1000ms);
}

struct service_events
{
    monitor_options options()
    {
        monitor_options opts;
        opts.mode = monitor_mode::discover;
        opts.on_found = [this](const resolved_service &svc) { found.push_back(svc); };
        opts.on_lost = [this](const resolved_service &svc, loss_reason reason)
        {
            lost.push_back(svc);
            reasons.push_back(reason);
        };
        return opts;
    }

    std::vector<resolved_service> found;
    std::vector<resolved_service> lost;
    std::vector<loss_reason> reasons;
};

struct live_server
{
    inproc_server server;

    live_server(inproc_harness &h, service_info info)
        : server{h.make_server(std::move(info))}
    {
        server.async_start();
        h.advance_to_live(server);
        h.executor.drain();
    }
};

struct live_monitor
{
    inproc_monitor monitor;

    live_monitor(inproc_harness &h, std::string_view type, monitor_options opts, mdns_options mdns_opts,
                 cache_options copts = {})
        : monitor{h.make_monitor(std::move(opts), {}, std::move(mdns_opts), std::move(copts))}
    {
        monitor.watch(type);
        monitor.async_start();
        h.executor.drain();
    }
};

struct live_observer
{
    inproc_observer observer;

    live_observer(inproc_harness &h, observer_options opts)
        : observer{h.make_observer(std::move(opts))}
    {
        observer.async_observe();
        h.executor.drain();
    }
};

#endif
