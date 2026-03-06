#ifndef HPP_GUARD_MDNSPP_SOCKET_OPTIONS_H
#define HPP_GUARD_MDNSPP_SOCKET_OPTIONS_H

#include <string>
#include <cstdint>
#include <optional>

namespace mdnspp {

enum class loopback_mode { enabled, disabled };

struct socket_options
{
    std::string interface_address{};
    std::optional<loopback_mode> multicast_loopback{};
    std::optional<std::uint8_t> multicast_ttl{};
};

}

#endif
