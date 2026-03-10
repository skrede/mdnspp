#ifndef HPP_GUARD_MDNSPP_VALIDATE_MULTICAST_H
#define HPP_GUARD_MDNSPP_VALIDATE_MULTICAST_H

#include <string>
#include <system_error>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#endif

namespace mdnspp::detail {

/// Validates that the given address string is a multicast address.
/// IPv4: 224.0.0.0/4 (first octet 224-239)
/// IPv6: ff00::/8 (first byte 0xFF)
/// Sets ec on failure; clears it on success.
inline void validate_multicast_address(const std::string &address, std::error_code &ec)
{
    ec.clear();

    if(address.empty())
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return;
    }

    // Try IPv4 first
    in_addr addr4{};
    if(::inet_pton(AF_INET, address.c_str(), &addr4) == 1)
    {
        auto first_octet = (ntohl(addr4.s_addr) >> 24) & 0xFF;
        if(first_octet >= 224 && first_octet <= 239)
            return;
        ec = std::make_error_code(std::errc::invalid_argument);
        return;
    }

    // Try IPv6
    in6_addr addr6{};
    if(::inet_pton(AF_INET6, address.c_str(), &addr6) == 1)
    {
        if(addr6.s6_addr[0] == 0xFF)
            return;
        ec = std::make_error_code(std::errc::invalid_argument);
        return;
    }

    // Neither family parsed successfully
    ec = std::make_error_code(std::errc::invalid_argument);
}

/// Throwing overload -- throws std::system_error with descriptive message on failure.
inline void validate_multicast_address(const std::string &address)
{
    std::error_code ec;
    validate_multicast_address(address, ec);
    if(ec)
        throw std::system_error(ec, "not a multicast address: " + address);
}

}

#endif
