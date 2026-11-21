#ifndef HPP_GUARD_MDNSPP_SOCKET_OPTIONS_H
#define HPP_GUARD_MDNSPP_SOCKET_OPTIONS_H

#include "mdnspp/endpoint.h"

#include <string>
#include <cstdint>
#include <optional>

namespace mdnspp {

enum class loopback_mode : uint8_t { enabled, disabled };

struct socket_options
{
    std::string interface_address{};
    std::optional<std::string> interface_name{};  // e.g. "eth0", "en0"
    std::optional<uint32_t> interface_index{};    // OS interface index
    endpoint multicast_group{"224.0.0.251", 5353};
    loopback_mode multicast_loopback{loopback_mode::enabled};
    std::optional<std::uint8_t> multicast_ttl{};
};

}

#endif
