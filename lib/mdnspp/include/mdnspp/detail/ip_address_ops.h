#ifndef HPP_GUARD_MDNSPP_DETAIL_IP_ADDRESS_OPS_H
#define HPP_GUARD_MDNSPP_DETAIL_IP_ADDRESS_OPS_H

#include "mdnspp/detail/native_socket.h"
#include "mdnspp/detail/native_sockaddr.h"

#include "mdnspp/ip_address.h"

#include <bit>
#include <span>
#include <tuple>
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

inline in_addr to_in_addr(const ip_address &address) noexcept
{
    in_addr out{};
    std::memcpy(&out, address.bytes.data(), sizeof(out));
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

inline uint8_t prefix_from_netmask(const ip_address &netmask) noexcept
{
    int32_t bits = 0;
    for(const std::byte octet : std::span{netmask.bytes}.first(address_width(netmask.family)))
        bits += std::popcount(std::to_integer<uint8_t>(octet));
    return static_cast<uint8_t>(bits);
}

inline bool address_before(const ip_network &lhs, const ip_network &rhs) noexcept
{
    return std::tie(lhs.address.family, lhs.address.bytes, lhs.prefix_length) <
           std::tie(rhs.address.family, rhs.address.bytes, rhs.prefix_length);
}

// KAME-derived stacks (macOS) embed the scope of an fe80::/10 address in its bytes 2 and 3.
inline void clear_embedded_scope(ip_address &address) noexcept
{
    const bool link_local = address.family == address_family::ipv6 && address.bytes[0] == std::byte{0xFE} &&
                            (address.bytes[1] & std::byte{0xC0}) == std::byte{0x80};
    if(link_local)
        address.bytes[2] = address.bytes[3] = std::byte{0};
}

}

#endif
