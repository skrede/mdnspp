#ifndef HPP_GUARD_MDNSPP_DETAIL_VALIDATE_MULTICAST_H
#define HPP_GUARD_MDNSPP_DETAIL_VALIDATE_MULTICAST_H

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#endif

#include <string>
#include <system_error>

namespace mdnspp::detail {

// 224.0.0.0/4 (RFC 5771)
inline bool is_ipv4_multicast(const in_addr &addr4)
{
    auto first_octet = (ntohl(addr4.s_addr) >> 24) & 0xFF;
    return first_octet >= 224 && first_octet <= 239;
}

// ff00::/8 (RFC 4291 section 2.7)
inline bool is_ipv6_multicast(const in6_addr &addr6)
{
    return addr6.s6_addr[0] == 0xFF;
}

inline void validate_multicast_address(const std::string &address, std::error_code &ec)
{
    ec.clear();

    if(address.empty())
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return;
    }

    in_addr addr4{};
    if(::inet_pton(AF_INET, address.c_str(), &addr4) == 1)
    {
        if(!is_ipv4_multicast(addr4))
            ec = std::make_error_code(std::errc::invalid_argument);
        return;
    }

    in6_addr addr6{};
    if(::inet_pton(AF_INET6, address.c_str(), &addr6) != 1 || !is_ipv6_multicast(addr6))
        ec = std::make_error_code(std::errc::invalid_argument);
}

inline void validate_multicast_address(const std::string &address)
{
    std::error_code ec;
    validate_multicast_address(address, ec);
    if(ec)
        throw std::system_error(ec, "not a multicast address: " + address);
}

}

#endif
