#ifndef HPP_GUARD_MDNSPP_INPROC_INPROC_HARNESS_H
#define HPP_GUARD_MDNSPP_INPROC_INPROC_HARNESS_H

#include "mdnspp/inproc/inproc_bus.h"
#include "mdnspp/inproc/inproc_policy.h"
#include "mdnspp/inproc/inproc_executor.h"

#include "mdnspp/service_info.h"
#include "mdnspp/cache_options.h"
#include "mdnspp/query_options.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/monitor_options.h"
#include "mdnspp/service_options.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/observer_options.h"
#include "mdnspp/basic_querier.h"
#include "mdnspp/basic_observer.h"
#include "mdnspp/basic_service_server.h"
#include "mdnspp/basic_service_monitor.h"
#include "mdnspp/testing/test_clock.h"

#include <chrono>

namespace mdnspp::inproc {

// inproc_harness — shared test fixture for multi-party in-process bus integration tests.
//
// Provides factory methods for all basic_* types wired to the same shared executor
// and bus. advance() steps the test_clock and drains all events to quiescence.
// advance_to_live() drives a server through the full probe/announce ceremony.
struct inproc_harness
{
    inproc_harness()
    {
        testing::test_clock::reset();
    }

    inproc_bus<testing::test_clock>      bus;
    inproc_executor<testing::test_clock> executor{bus};

    // Advance the test clock by d, then drain all events to quiescence.
    void advance(std::chrono::milliseconds d)
    {
        testing::test_clock::advance(d);
        executor.drain();
    }

    // Create a basic_service_server<inproc_test_policy> with the shared executor.
    basic_service_server<inproc_test_policy> make_server(service_info info,
                                                       service_options opts = {},
                                                       socket_options sock_opts = {},
                                                       mdns_options mdns_opts = {})
    {
        return basic_service_server<inproc_test_policy>{
            executor, std::move(info), std::move(opts),
            std::move(sock_opts), std::move(mdns_opts)};
    }

    // Create a basic_service_monitor<inproc_test_policy, test_clock> with the shared executor.
    basic_service_monitor<inproc_test_policy, testing::test_clock>
    make_monitor(monitor_options opts = {},
                 socket_options sock_opts = {},
                 mdns_options mdns_opts = {},
                 cache_options copts = {})
    {
        return basic_service_monitor<inproc_test_policy, testing::test_clock>{
            executor, std::move(opts), std::move(sock_opts),
            std::move(mdns_opts), std::move(copts)};
    }

    // Create a basic_querier<inproc_test_policy> with the shared executor.
    basic_querier<inproc_test_policy> make_querier(query_options opts = {},
                                                 socket_options sock_opts = {},
                                                 mdns_options mdns_opts = {})
    {
        return basic_querier<inproc_test_policy>{
            executor, std::move(opts), std::move(sock_opts), std::move(mdns_opts)};
    }

    // Create a basic_observer<inproc_test_policy> with the shared executor.
    basic_observer<inproc_test_policy> make_observer(observer_options opts = {},
                                                   socket_options sock_opts = {},
                                                   mdns_options mdns_opts = {})
    {
        return basic_observer<inproc_test_policy>{
            executor, std::move(opts), std::move(sock_opts), std::move(mdns_opts)};
    }

    // Step a server from constructed through probe/announce to live state.
    //
    // Uses service_options defaults:
    //   probe_initial_delay_max = 250ms  (advance past random [0, 250ms] initial delay)
    //   probe_interval          = 250ms  (probes 2 and 3)
    //   probe_count             = 3      (conflict window expires after probe 3)
    //   announce_count          = 2      (first announce immediate, second after 1000ms)
    //   announce_interval       = 1000ms
    //
    // Total wall-clock time advanced: 250+250+250+250+1000 = 2000ms
    //
    // An optional service_options parameter allows extracting actual timing values
    // when non-default options were used.
    void advance_to_live(basic_service_server<inproc_test_policy> &server,
                         service_options opts = {})
    {
        // Advance past the random initial delay [0, probe_initial_delay_max].
        // Using the maximum ensures the first probe fires regardless of the RNG result.
        advance(opts.probe_initial_delay_max);

        // Probes 2 and 3: two more probe_interval advances.
        advance(opts.probe_interval);
        advance(opts.probe_interval);

        // Conflict window: one more probe_interval for the silence window after probe 3.
        advance(opts.probe_interval);

        // First announcement is sent immediately when announcing begins.
        // Second (and any additional) announcements require announce_interval advances.
        for(uint8_t i = 1; i < opts.announce_count; ++i)
            advance(opts.announce_interval);

        (void)server; // server state is mutated via the shared executor/bus
    }
};

}

#endif
