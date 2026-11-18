#ifndef HPP_GUARD_MDNSPP_SOCKET_OPTIONS_H
#define HPP_GUARD_MDNSPP_SOCKET_OPTIONS_H

#include "mdnspp/endpoint.h"

#include <string>
#include <cstdint>
#include <optional>

namespace mdnspp {

enum class loopback_mode : uint8_t { enabled, disabled };

// socket_options — multicast socket configuration shared by all peers.
//
// Interface selection: at socket open, the binding fields are resolved with
// the precedence interface_index > interface_name > interface_address. An
// interface_index or interface_name is translated to that interface's address
// of the socket's family (see below) via enumerate_interfaces(); an unknown
// index or name, or a matching interface without an address of the required
// family, fails socket construction with std::errc::invalid_argument. When
// all three fields are unset/empty the socket binds to all interfaces
// (INADDR_ANY / in6addr_any).
//
// Address family: the family of multicast_group.address selects the socket
// family. interface_address must then be an address of the same family — a
// dotted-decimal IPv4 address for IPv4 sockets, or a colon-hex IPv6 address
// for IPv6 sockets (translated internally to the owning interface's index for
// IPV6_MULTICAST_IF / IPV6_JOIN_GROUP).
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
