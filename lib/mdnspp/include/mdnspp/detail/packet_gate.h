#ifndef HPP_GUARD_MDNSPP_DETAIL_PACKET_GATE_H
#define HPP_GUARD_MDNSPP_DETAIL_PACKET_GATE_H

#include "mdnspp/detail/dns_frame.h"
#include "mdnspp/detail/gate_rules.h"
#include "mdnspp/detail/recv_filter.h"
#include "mdnspp/detail/policy_clock.h"
#include "mdnspp/detail/on_link_table.h"
#include "mdnspp/detail/ip_address_ops.h"
#include "mdnspp/detail/transport_traits.h"

#include "mdnspp/policy.h"
#include "mdnspp/ip_address.h"
#include "mdnspp/mdns_options.h"

#include <span>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <optional>
#include <string_view>

namespace mdnspp::detail {

template <policy_like P>
class packet_gate
{
public:
    using enumerator = typename on_link_table<policy_clock_t<P>>::enumerator;

    packet_gate(uint16_t multicast_port, uint32_t receive_ttl_minimum, ttl_unknown_policy unknown_ttl_policy,
                uint32_t bound_ifindex, enumerator enumerate)
        : m_bound_ifindex(bound_ifindex)
        , m_multicast_port(multicast_port)
        , m_receive_ttl_minimum(receive_ttl_minimum)
        , m_unknown_ttl_policy(unknown_ttl_policy)
        , m_on_link(std::move(enumerate))
    {
    }

    bool admit(const recv_metadata &meta, std::span<const std::byte> data)
    {
        if(data.size() < dns_frame_header_size)
            return false;
        const dns_frame_header header = read_frame_header(data);
        if(!header_accepted(header) || interface_mismatch(meta, m_bound_ifindex))
            return false;
        if(!header.is_response())
            return query_accepted(meta);
        return response_port_accepted(meta, m_multicast_port, in_process)
            && ttl_accepted(meta, m_receive_ttl_minimum, m_unknown_ttl_policy) && response_on_link(meta);
    }

private:
    uint32_t m_bound_ifindex;
    uint16_t m_multicast_port;
    uint32_t m_receive_ttl_minimum;
    ttl_unknown_policy m_unknown_ttl_policy;
    on_link_table<policy_clock_t<P>> m_on_link;
    static constexpr bool in_process = is_in_process_v<typename P::socket_type>;

    // Queries skip the TTL rule: legacy queriers often send with IP TTL 1 and are owed a reply (RFC 6762 section 6.7).
    // RFC 6762 section 5.5: "responders SHOULD check that the source address in the query packet matches the local
    // subnet for that link". An unknown destination is never held against a query.
    bool query_accepted(const recv_metadata &meta)
    {
        return in_process || classify_destination(meta) != destination_kind::unicast || source_on_link(meta);
    }

    // RFC 6762 section 11: "All responses received with a destination address in the IP header that is the mDNS IPv4
    // link-local multicast address 224.0.0.251 or the mDNS IPv6 link-local multicast address FF02::FB are necessarily
    // deemed to have originated on the local link". Any multicast destination counts, so a configured group does too.
    bool response_on_link(const recv_metadata &meta)
    {
        return in_process || classify_destination(meta) == destination_kind::multicast || source_on_link(meta);
    }

    // The zone is dropped unparsed: resolving an interface name would cost a system call per packet.
    bool source_on_link(const recv_metadata &meta)
    {
        const std::string_view text = meta.sender.address;
        const std::optional<ip_address> source = parse_ip_address(text.substr(0, text.find('%')));
        return source && m_on_link.on_link(*source, meta.recv_ifindex, m_bound_ifindex);
    }
};

}

#endif
