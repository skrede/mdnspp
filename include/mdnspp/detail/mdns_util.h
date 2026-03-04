#ifndef HPP_GUARD_MDNSPP_DETAIL_MDNS_UTIL_H
#define HPP_GUARD_MDNSPP_DETAIL_MDNS_UTIL_H

#include "mdnspp/detail/platform.h"
#ifndef _WIN32
#  include <netdb.h>
#endif

#include <string>

namespace mdnspp {

std::string ip_address_to_string(const sockaddr *addr, size_t addrlen);
std::string ip_address_to_string(const sockaddr_in &addr);
std::string ip_address_to_string(const sockaddr_in6 &addr);

}

#endif
