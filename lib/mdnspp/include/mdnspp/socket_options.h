#ifndef HPP_GUARD_MDNSPP_SOCKET_OPTIONS_H
#define HPP_GUARD_MDNSPP_SOCKET_OPTIONS_H

#include "mdnspp/endpoint.h"

#include <string>
#include <cstdint>
#include <optional>

namespace mdnspp {

enum class loopback_mode { enabled, disabled };

struct socket_options
{
    std::string interface_address{};
    endpoint multicast_group{"224.0.0.251", 5353};
    loopback_mode multicast_loopback{loopback_mode::enabled};
    std::optional<std::uint8_t> multicast_ttl{};
};

}

#endif
