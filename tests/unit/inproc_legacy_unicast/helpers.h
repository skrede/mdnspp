#ifndef HPP_GUARD_MDNSPP_INPROC_LEGACY_UNICAST_HELPERS_H
#define HPP_GUARD_MDNSPP_INPROC_LEGACY_UNICAST_HELPERS_H

#include "mdnspp/inproc/inproc_socket.h"
#include "mdnspp/inproc/inproc_harness.h"
#include "mdnspp/inproc/inproc_socket_options.h"

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/service_info.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/service_options.h"
#include "mdnspp/observer_options.h"

#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_query.h"

#include <span>
#include <string>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <string_view>

using namespace mdnspp;
using mdnspp::inproc::inproc_harness;
using mdnspp::inproc::inproc_socket;
using mdnspp::testing::test_clock;

using inproc_server = basic_service_server<inproc_test_policy>;
using inproc_observer = basic_observer<inproc_test_policy>;

inline service_info make_service(std::string_view name, std::string_view type, std::string_view host, uint16_t port)
{
    service_info info;
    info.service_name = std::string(name);
    info.service_type = std::string(type);
    info.hostname = std::string(host);
    info.port = port;
    info.address_ipv4 = "192.168.1.1";
    return info;
}

inline service_options legacy_aware_opts()
{
    service_options opts;
    opts.respond_to_legacy_unicast = true;
    opts.respond_to_meta_queries = false;
    return opts;
}

inline inproc::inproc_socket_options no_loopback()
{
    inproc::inproc_socket_options opts;
    opts.multicast_loopback = loopback_mode::disabled;
    return opts;
}

inline endpoint mdns_multicast_ep()
{
    return endpoint{"224.0.0.251", 5353};
}

inline void send_ptr_query(inproc_socket<test_clock> &client)
{
    auto query = detail::build_dns_query("_http._tcp.local.", dns_type::ptr);
    client.send(mdns_multicast_ep(), std::span<const std::byte>(query));
}

// Sockets queue bus traffic from construction on, so the fixtures build the server, then the observer, then the
// querying client, each after the previous one's traffic has drained.
struct live_server
{
    inproc_server server;

    live_server(inproc_harness &h, service_info info, service_options opts, mdns_options mdns_opts)
        : server{h.make_server(std::move(info), std::move(opts), no_loopback(), std::move(mdns_opts))}
    {
        server.async_start();
        h.advance_to_live(server);
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
