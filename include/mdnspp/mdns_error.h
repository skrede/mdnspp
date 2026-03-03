#ifndef MDNSPP_MDNS_ERROR_H
#define MDNSPP_MDNS_ERROR_H

#include <cstdint>

namespace mdnspp {

enum class mdns_error : uint32_t
{
    socket_error    = 1,
    no_interfaces   = 2,
    parse_error     = 3,
    send_failed     = 4,
    receive_failed  = 5,
    timeout         = 6,
    not_implemented = 7
};

} // namespace mdnspp

#endif // MDNSPP_MDNS_ERROR_H
