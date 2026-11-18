#ifndef HPP_GUARD_MDNSPP_DETAIL_SOCKADDR_TEXT_H
#define HPP_GUARD_MDNSPP_DETAIL_SOCKADDR_TEXT_H

#include "mdnspp/detail/native_socket.h"

#include "mdnspp/endpoint.h"

#include <cstddef>

namespace mdnspp::detail {

// The longest IPv6 text (INET6_ADDRSTRLEN) plus a '%' and a numeric zone suffix.
inline constexpr std::size_t max_address_text = 64;

// Assigning into a string whose capacity already covers the text does not allocate.
inline void assign_endpoint(const sockaddr_storage &addr, endpoint &out)
{
    char text[INET6_ADDRSTRLEN]{};
    if(addr.ss_family == AF_INET6)
    {
        const auto &sa6 = reinterpret_cast<const sockaddr_in6 &>(addr);
        ::inet_ntop(AF_INET6, &sa6.sin6_addr, text, sizeof(text));
        out.port = ntohs(sa6.sin6_port);
    }
    else
    {
        const auto &sa4 = reinterpret_cast<const sockaddr_in &>(addr);
        ::inet_ntop(AF_INET, &sa4.sin_addr, text, sizeof(text));
        out.port = ntohs(sa4.sin_port);
    }
    out.address.assign(text);
}

inline endpoint reserved_endpoint()
{
    endpoint ep{};
    ep.address.reserve(max_address_text);
    return ep;
}

}

#endif
