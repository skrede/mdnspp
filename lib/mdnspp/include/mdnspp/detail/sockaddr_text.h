#ifndef HPP_GUARD_MDNSPP_DETAIL_SOCKADDR_TEXT_H
#define HPP_GUARD_MDNSPP_DETAIL_SOCKADDR_TEXT_H

#include "mdnspp/detail/native_socket.h"

#include "mdnspp/endpoint.h"

#include <cstddef>
#include <cstring>
#include <charconv>

namespace mdnspp::detail {

// The longest IPv6 text (INET6_ADDRSTRLEN) plus a '%' and a numeric zone suffix.
inline constexpr std::size_t max_address_text = 64;

inline bool is_link_local(const in6_addr &addr)
{
    return addr.s6_addr[0] == 0xfe && (addr.s6_addr[1] & 0xc0) == 0x80;
}

// RFC 4007 section 11: a link-local address is ambiguous without its zone, so the scope id
// is appended as a numeric zone index for a reply to leave through the receiving interface.
inline void append_zone(const sockaddr_in6 &sa6, char (&text)[max_address_text])
{
    if(sa6.sin6_scope_id == 0 || !is_link_local(sa6.sin6_addr))
        return;
    const std::size_t len = std::strlen(text);
    char *const end = text + max_address_text - 1;
    text[len] = '%';
    *std::to_chars(text + len + 1, end, sa6.sin6_scope_id).ptr = '\0';
}

// Assigning into a string whose capacity already covers the text does not allocate.
inline void assign_endpoint(const sockaddr_storage &addr, endpoint &out)
{
    char text[max_address_text]{};
    if(addr.ss_family == AF_INET6)
    {
        const auto &sa6 = reinterpret_cast<const sockaddr_in6 &>(addr);
        ::inet_ntop(AF_INET6, &sa6.sin6_addr, text, sizeof(text));
        append_zone(sa6, text);
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
