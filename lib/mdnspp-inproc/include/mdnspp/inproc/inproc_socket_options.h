#ifndef HPP_GUARD_MDNSPP_INPROC_INPROC_SOCKET_OPTIONS_H
#define HPP_GUARD_MDNSPP_INPROC_INPROC_SOCKET_OPTIONS_H

#include "mdnspp/socket_options.h"

#include <cstdint>
#include <optional>

namespace mdnspp::inproc {

struct inproc_socket_options : socket_options
{
    /// Override the port assigned by inproc_bus::register_socket. When set,
    /// the inproc_socket is assigned the given port instead of the bus default
    /// (start_port). Simulates legacy unicast clients that query from a source
    /// port other than 5353 (RFC 6762 §6.7).
    std::optional<uint16_t> port_override{};
};

}

#endif
