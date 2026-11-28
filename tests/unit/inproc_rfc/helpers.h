#ifndef HPP_GUARD_MDNSPP_INPROC_RFC_HELPERS_H
#define HPP_GUARD_MDNSPP_INPROC_RFC_HELPERS_H

#include "mdnspp/inproc/inproc_socket.h"
#include "mdnspp/inproc/inproc_harness.h"

#include "mdnspp/mdns_options.h"
#include "mdnspp/service_info.h"
#include "mdnspp/monitor_options.h"
#include "mdnspp/service_options.h"
#include "mdnspp/observer_options.h"
#include "mdnspp/resolved_service.h"

#include <span>
#include <chrono>
#include <string>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <variant>
#include <string_view>

using namespace mdnspp;
using namespace std::chrono_literals;
using mdnspp::inproc::inproc_harness;
using mdnspp::inproc::inproc_socket;
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

inline mdns_options fast_response_opts(std::chrono::milliseconds delay = 1ms)
{
    mdns_options opts = fast_scheduler_opts();
    opts.response_delay_min = delay;
    opts.response_delay_max = delay;
    return opts;
}

inline endpoint mdns_multicast_ep()
{
    return endpoint{"224.0.0.251", 5353};
}

// The transient injector deregisters from the bus on destruction; the packet stays queued until the next drain().
inline void inject(inproc_harness &h, std::span<const std::byte> data)
{
    inproc_socket<test_clock> injector{h.executor};
    injector.send(mdns_multicast_ep(), data);
}

// Sockets queue bus traffic from construction on, so a server built and brought live here, before the fixture's
// monitors or observers exist, keeps its probes and announcements out of their receive queues.
struct live_server
{
    inproc_server server;

    live_server(inproc_harness &h, service_info info, service_options opts, mdns_options mdns_opts,
                inproc::inproc_socket_options sock_opts = {})
        : server{h.make_server(std::move(info), std::move(opts), std::move(sock_opts), std::move(mdns_opts))}
    {
        server.async_start();
        h.advance_to_live(server);
        h.executor.drain();
    }
};

inline monitor_options count_found(int32_t &found)
{
    monitor_options opts;
    opts.mode = monitor_mode::discover;
    opts.on_found = [&found](const resolved_service &) { ++found; };
    return opts;
}

inline observer_options count_service_ptrs(int32_t &count)
{
    observer_options opts;
    opts.on_record = [&count](const endpoint &, const mdns_record_variant &rec)
    {
        if(std::holds_alternative<record_ptr>(rec) && std::get<record_ptr>(rec).name == "_http._tcp.local.")
            ++count;
    };
    return opts;
}

#endif
