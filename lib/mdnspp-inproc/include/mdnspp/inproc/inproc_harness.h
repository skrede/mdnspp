#ifndef HPP_GUARD_MDNSPP_INPROC_INPROC_HARNESS_H
#define HPP_GUARD_MDNSPP_INPROC_INPROC_HARNESS_H

#include "mdnspp/inproc/inproc_bus.h"
#include "mdnspp/inproc/inproc_policy.h"
#include "mdnspp/inproc/inproc_executor.h"
#include "mdnspp/inproc/inproc_socket_options.h"

#include "mdnspp/mdns_options.h"
#include "mdnspp/service_info.h"
#include "mdnspp/basic_querier.h"
#include "mdnspp/cache_options.h"
#include "mdnspp/query_options.h"
#include "mdnspp/basic_observer.h"
#include "mdnspp/monitor_options.h"
#include "mdnspp/service_options.h"
#include "mdnspp/observer_options.h"
#include "mdnspp/basic_service_server.h"
#include "mdnspp/basic_service_monitor.h"

#include "mdnspp/testing/test_clock.h"

#include <chrono>
#include <cstdint>

namespace mdnspp::inproc {

struct inproc_harness
{
    inproc_harness()
        : bus()
        , executor(bus)
    {
        testing::test_clock::reset();
    }

    inproc_bus<testing::test_clock>      bus;
    inproc_executor<testing::test_clock> executor;

    void advance(std::chrono::milliseconds d)
    {
        testing::test_clock::advance(d);
        executor.drain();
    }

    basic_service_server<inproc_test_policy> make_server(service_info info,
                                                       service_options opts = {},
                                                       inproc_socket_options sock_opts = {},
                                                       mdns_options mdns_opts = {})
    {
        return basic_service_server<inproc_test_policy>{
            executor, std::move(info), std::move(opts),
            std::move(sock_opts), std::move(mdns_opts)};
    }

    basic_service_monitor<inproc_test_policy, testing::test_clock>
    make_monitor(monitor_options opts = {},
                 inproc_socket_options sock_opts = {},
                 mdns_options mdns_opts = {},
                 cache_options copts = {})
    {
        return basic_service_monitor<inproc_test_policy, testing::test_clock>{
            executor, std::move(opts), std::move(sock_opts),
            std::move(mdns_opts), std::move(copts)};
    }

    basic_querier<inproc_test_policy> make_querier(query_options opts = {},
                                                 inproc_socket_options sock_opts = {},
                                                 mdns_options mdns_opts = {})
    {
        return basic_querier<inproc_test_policy>{
            executor, std::move(opts), std::move(sock_opts), std::move(mdns_opts)};
    }

    basic_observer<inproc_test_policy> make_observer(observer_options opts = {},
                                                   inproc_socket_options sock_opts = {},
                                                   mdns_options mdns_opts = {})
    {
        return basic_observer<inproc_test_policy>{
            executor, std::move(opts), std::move(sock_opts), std::move(mdns_opts)};
    }

    // The maximum initial delay fires the first probe whatever the random draw; probe_count probe intervals then
    // cover probes 2 to probe_count and the conflict window after the last probe. The first announcement is immediate.
    void advance_to_live(basic_service_server<inproc_test_policy> &server,
                         service_options opts = {})
    {
        advance(opts.probe_initial_delay_max);
        for(uint8_t i = 0; i < opts.probe_count; ++i)
            advance(opts.probe_interval);
        for(uint8_t i = 1; i < opts.announce_count; ++i)
            advance(opts.announce_interval);
        (void)server;
    }
};

}

#endif
