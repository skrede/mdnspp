#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_CONTEXT_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_CONTEXT_H

#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_frame.h"
#include "mdnspp/detail/address_encode.h"
#include "mdnspp/detail/interface_resolve.h"
#include "mdnspp/detail/server_probe_announce.h"

#include "mdnspp/policy.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_error.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/service_info.h"
#include "mdnspp/service_options.h"
#include "mdnspp/network_interface.h"

#include <span>
#include <atomic>
#include <random>
#include <string>
#include <vector>
#include <cstddef>
#include <utility>
#include <string_view>
#include <system_error>

namespace mdnspp::detail {

inline std::vector<mdns_record_variant> parse_answer_records(std::span<const std::byte> data)
{
    std::vector<mdns_record_variant> records;
    walk_dns_frame(data, endpoint{}, [&](mdns_record_variant rv)
    {
        records.push_back(std::move(rv));
    });
    return records;
}

// Delayed responses run on their own timer: an update announcement burst can overlap a pending delayed
// response while live, and a shared timer would let the announcement's expires_after cancel the response.
template <policy_like P>
class server_context
{
public:
    using executor_type = typename P::executor_type;
    using socket_type = typename P::socket_type;
    using timer_type = typename P::timer_type;

    server_context(executor_type ex, service_info service, service_options options, interface_binding bound_to,
                   socket_type &socket, const endpoint &multicast, const mdns_options &mdns,
                   const std::atomic<bool> &stopped_flag)
        : response_timer(ex)
        , delay_timer(ex)
        , tc_timer(ex)
        , info(std::move(service))
        , opts(std::move(options))
        , rng(std::random_device{}())
        , binding(std::move(bound_to))
        , pa_state()
        , mdns_opts(mdns)
        , m_socket(socket)
        , m_multicast(multicast)
        , m_stopped(stopped_flag)
    {
    }

    bool stopped() const noexcept { return m_stopped.load(std::memory_order_acquire); }

    void report_error(std::error_code ec, std::string_view context)
    {
        if(ec && opts.on_error)
            opts.on_error(ec, context);
    }

    void send_to(response_mode mode, const endpoint &sender, std::span<const std::byte> packet,
                 std::string_view context)
    {
        std::error_code ec;
        if(mode == response_mode::unicast)
            m_socket.send(sender, packet, ec);
        else
            m_socket.send(m_multicast, packet, ec);
        report_error(ec, context);
    }

    // RFC 6762 section 6.2: advertised addresses must be valid on the announcing link.
    void resolve_auto_addresses()
    {
        if(!info.auto_address)
            return;
        std::error_code ec;
        auto interfaces = enumerate_interfaces(ec);
        if(ec)
        {
            report_error(ec, "interface enumeration");
            return;
        }
        resolve_advertised_addresses(interfaces, binding, info);
    }

    void validate_addresses()
    {
        if(info.address_ipv4.has_value())
        {
            auto enc = encode_ipv4(*info.address_ipv4);
            if(!enc.has_value())
                report_error(make_error_code(enc.error()), "invalid IPv4 address: " + *info.address_ipv4);
        }
        if(info.address_ipv6.has_value())
        {
            auto enc = encode_ipv6(*info.address_ipv6);
            if(!enc.has_value())
                report_error(make_error_code(enc.error()), "invalid IPv6 address: " + *info.address_ipv6);
        }
    }

    timer_type response_timer;
    timer_type delay_timer;
    timer_type tc_timer;
    service_info info;
    service_options opts;
    std::mt19937 rng;
    interface_binding binding;
    probe_announce_state pa_state;
    const mdns_options &mdns_opts;

private:
    socket_type &m_socket;
    const endpoint &m_multicast;
    const std::atomic<bool> &m_stopped;
};

}

#endif
