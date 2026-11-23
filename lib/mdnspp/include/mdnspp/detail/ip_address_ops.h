#ifndef HPP_GUARD_MDNSPP_DETAIL_IP_ADDRESS_OPS_H
#define HPP_GUARD_MDNSPP_DETAIL_IP_ADDRESS_OPS_H

#include "mdnspp/detail/native_socket.h"
#include "mdnspp/detail/native_sockaddr.h"

#include "mdnspp/ip_address.h"

#include <span>
#include <string>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <algorithm>
#include <string_view>

namespace mdnspp::detail {

inline std::size_t address_width(address_family family) noexcept
{
    return family == address_family::ipv4 ? 4 : 16;
}

inline ip_address to_ip_address(const in_addr &addr) noexcept
{
    ip_address out{.family = address_family::ipv4};
    std::memcpy(out.bytes.data(), &addr, sizeof(addr));
    return out;
}

inline ip_address to_ip_address(const in6_addr &addr) noexcept
{
    ip_address out{.family = address_family::ipv6};
    std::memcpy(out.bytes.data(), &addr, sizeof(addr));
    return out;
}

inline std::optional<ip_address> parse_ip_address(std::string_view text)
{
    sockaddr_in addr4{};
    if(parse_ipv4(text, addr4))
        return to_ip_address(addr4.sin_addr);
    sockaddr_in6 addr6{};
    if(parse_ipv6(text, addr6))
        return to_ip_address(addr6.sin6_addr);
    return std::nullopt;
}

inline std::string format_ip_address(const ip_address &address)
{
    char text[INET6_ADDRSTRLEN]{};
    const int family = address.family == address_family::ipv4 ? AF_INET : AF_INET6;
    ::inet_ntop(family, address.bytes.data(), text, sizeof(text));
    return text;
}

inline bool in_prefix(const ip_address &address, const ip_address &prefix, uint8_t length) noexcept
{
    if(address.family != prefix.family || static_cast<std::size_t>(length) > address_width(address.family) * 8)
        return false;
    const std::size_t whole = length / 8u;
    if(!std::ranges::equal(std::span{address.bytes}.first(whole), std::span{prefix.bytes}.first(whole)))
        return false;
    const auto remainder = static_cast<uint32_t>(length % 8u);
    if(remainder == 0)
        return true;
    const auto mask = std::byte{static_cast<uint8_t>(0xFFu << (8u - remainder))};
    return (address.bytes[whole] & mask) == (prefix.bytes[whole] & mask);
}

}

#endif
