#ifndef HPP_GUARD_MDNSPP_DETAIL_PACKET_GATE_H
#define HPP_GUARD_MDNSPP_DETAIL_PACKET_GATE_H

#include "mdnspp/detail/dns_frame.h"
#include "mdnspp/detail/gate_rules.h"
#include "mdnspp/detail/transport_traits.h"

#include "mdnspp/policy.h"

#include <span>
#include <cstddef>
#include <cstdint>

namespace mdnspp::detail {

template <policy_like P>
class packet_gate
{
public:
    explicit packet_gate(uint16_t multicast_port) noexcept
        : m_multicast_port(multicast_port)
    {
    }

    bool admit(const recv_metadata &meta, std::span<const std::byte> data) const noexcept
    {
        if(data.size() < dns_frame_header_size)
            return false;
        const dns_frame_header header = read_frame_header(data);
        if(!header_accepted(header))
            return false;
        return !header.is_response()
            || response_port_accepted(meta, m_multicast_port, is_in_process_v<typename P::socket_type>);
    }

private:
    uint16_t m_multicast_port;
};

}

#endif
