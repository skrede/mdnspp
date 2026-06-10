#ifndef HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPT_SOCKET_OPTIONS_H
#define HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPT_SOCKET_OPTIONS_H

#include "mdnspp/socket_options.h"
#include "mdnspp/encrypt/encrypt_options.h"

namespace mdnspp::encrypt {

struct encrypt_socket_options : socket_options
{
    encrypt_options encrypt{};
};

}

#endif
