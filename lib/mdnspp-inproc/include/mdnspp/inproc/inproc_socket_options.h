#ifndef HPP_GUARD_MDNSPP_INPROC_INPROC_SOCKET_OPTIONS_H
#define HPP_GUARD_MDNSPP_INPROC_INPROC_SOCKET_OPTIONS_H

#include "mdnspp/socket_options.h"

#include <cstdint>
#include <optional>

namespace mdnspp::inproc {

struct inproc_socket_options : socket_options
{
    std::optional<uint16_t> port_override{};
};

}

#endif
