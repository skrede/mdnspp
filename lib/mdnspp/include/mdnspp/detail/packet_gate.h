#ifndef HPP_GUARD_MDNSPP_DETAIL_PACKET_GATE_H
#define HPP_GUARD_MDNSPP_DETAIL_PACKET_GATE_H

#include "mdnspp/detail/dns_frame.h"
#include "mdnspp/detail/gate_rules.h"
#include "mdnspp/detail/recv_filter.h"
#include "mdnspp/detail/transport_traits.h"

#include "mdnspp/policy.h"
#include "mdnspp/mdns_options.h"

#include <span>
#include <cstddef>
#include <cstdint>

namespace mdnspp::detail {

template <policy_like P>
class packet_gate
{
public:
    packet_gate(uint16_t multicast_port, uint32_t receive_ttl_minimum, ttl_unknown_policy unknown_ttl_policy) noexcept
        : m_multicast_port(multicast_port)
        , m_receive_ttl_minimum(receive_ttl_minimum)
        , m_unknown_ttl_policy(unknown_ttl_policy)
    {
    }

    bool admit(const recv_metadata &meta, std::span<const std::byte> data) const noexcept
    {
        if(data.size() < dns_frame_header_size)
            return false;
        const dns_frame_header header = read_frame_header(data);
        if(!header_accepted(header))
            return false;
        // Queries skip the TTL rule: legacy queriers often send with IP TTL 1 and are owed a reply
        // (RFC 6762 section 6.7).
        if(!header.is_response())
            return true;
        return response_port_accepted(meta, m_multicast_port, is_in_process_v<typename P::socket_type>)
            && ttl_accepted(meta, m_receive_ttl_minimum, m_unknown_ttl_policy);
    }

private:
    uint16_t m_multicast_port;
    uint32_t m_receive_ttl_minimum;
    ttl_unknown_policy m_unknown_ttl_policy;
};

}

#endif
