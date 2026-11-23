#ifndef HPP_GUARD_MDNSPP_DETAIL_GATE_RULES_H
#define HPP_GUARD_MDNSPP_DETAIL_GATE_RULES_H

#include "mdnspp/detail/dns_frame.h"

#include "mdnspp/policy.h"

#include <cstdint>

namespace mdnspp::detail {

enum class destination_kind : uint8_t
{
    multicast,
    unicast,
    unknown,
};

inline destination_kind classify_destination(const recv_metadata &meta) noexcept
{
    if(!meta.destination)
        return destination_kind::unknown;
    return meta.destination->is_multicast() ? destination_kind::multicast : destination_kind::unicast;
}

// RFC 6762 section 18.3: "Multicast DNS messages received with an OPCODE other than zero MUST be silently ignored."
// RFC 6762 section 18.11: "Multicast DNS messages received with non-zero Response Codes MUST be silently ignored."
inline bool header_accepted(const dns_frame_header &header) noexcept
{
    return header.opcode() == 0 && header.rcode() == 0;
}

// RFC 6762 section 6: "Multicast DNS implementations MUST silently ignore any Multicast DNS responses they receive
// where the source UDP port is not 5353." The configured multicast port stands in for 5353.
inline bool response_port_accepted(const recv_metadata &meta, uint16_t multicast_port, bool in_process) noexcept
{
    return in_process || meta.sender.port == multicast_port;
}

}

#endif
