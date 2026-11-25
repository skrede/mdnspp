#ifndef HPP_GUARD_MDNSPP_SOCKET_OPTIONS_H
#define HPP_GUARD_MDNSPP_SOCKET_OPTIONS_H

#include "mdnspp/endpoint.h"

#include <string>
#include <cstdint>
#include <optional>
#include <string_view>

namespace mdnspp {

enum class loopback_mode : uint8_t { enabled, disabled };

inline constexpr std::string_view default_ipv4_group = "224.0.0.251";
inline constexpr std::string_view default_ipv6_group = "ff02::fb";
inline constexpr uint16_t default_port = 5353;

struct socket_options
{
    std::string interface_address{};
    std::optional<std::string> interface_name{};  // e.g. "eth0", "en0"
    std::optional<uint32_t> interface_index{};    // OS interface index
    endpoint multicast_group{std::string{default_ipv4_group}, default_port};
    loopback_mode multicast_loopback{loopback_mode::enabled};
    std::optional<std::uint8_t> multicast_ttl{};
};

}

#endif
