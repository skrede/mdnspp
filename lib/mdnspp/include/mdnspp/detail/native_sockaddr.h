#ifndef HPP_GUARD_MDNSPP_DETAIL_NATIVE_SOCKADDR_H
#define HPP_GUARD_MDNSPP_DETAIL_NATIVE_SOCKADDR_H

#include "mdnspp/detail/native_socket.h"

#include "mdnspp/endpoint.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <charconv>
#include <optional>
#include <string_view>
#include <system_error>

#ifdef _WIN32
#  include <iphlpapi.h>
#else
#  include <net/if.h>
#endif

namespace mdnspp::detail {

template <std::size_t N>
bool copy_terminated(std::string_view text, std::array<char, N> &buf)
{
    if(text.size() >= N || text.find('\0') != std::string_view::npos)
        return false;
    buf[text.copy(buf.data(), text.size())] = '\0';
    return true;
}

inline bool parse_zone(std::string_view zone, uint32_t &scope)
{
    if(zone.empty())
        return false;
    const char *const end = zone.data() + zone.size();
    const auto [ptr, ec] = std::from_chars(zone.data(), end, scope);
    if(ec == std::errc{} && ptr == end)
        return true;
    std::array<char, IF_NAMESIZE> name{};
    if(!copy_terminated(zone, name))
        return false;
    scope = ::if_nametoindex(name.data());
    return scope != 0;
}

inline bool parse_ipv4(std::string_view text, sockaddr_in &out)
{
    std::array<char, INET_ADDRSTRLEN> addr{};
    return copy_terminated(text, addr) && ::inet_pton(AF_INET, addr.data(), &out.sin_addr) == 1;
}

// RFC 4007 section 11: the zone after '%' is a numeric index or an interface name.
inline bool parse_ipv6(std::string_view text, sockaddr_in6 &out)
{
    const std::size_t percent = text.find('%');
    std::array<char, INET6_ADDRSTRLEN> addr{};
    if(!copy_terminated(text.substr(0, percent), addr) || ::inet_pton(AF_INET6, addr.data(), &out.sin6_addr) != 1)
        return false;
    if(percent == std::string_view::npos)
        return true;
    uint32_t scope{};
    if(!parse_zone(text.substr(percent + 1), scope))
        return false;
    out.sin6_scope_id = scope;
    return true;
}

inline bool is_ipv6(std::string_view addr)
{
    sockaddr_in6 tmp{};
    return parse_ipv6(addr, tmp);
}

struct sockaddr_result
{
    sockaddr_storage ss;
    socklen_t len;
};

template <typename Sockaddr>
sockaddr_result make_sockaddr_result(const Sockaddr &addr)
{
    sockaddr_result r{};
    std::memcpy(&r.ss, &addr, sizeof(addr));
    r.len = sizeof(addr);
    return r;
}

inline std::optional<sockaddr_result> build_sockaddr(const endpoint &dest)
{
    sockaddr_in6 addr6{};
    if(parse_ipv6(dest.address, addr6))
    {
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(dest.port);
        return make_sockaddr_result(addr6);
    }
    sockaddr_in addr4{};
    if(!parse_ipv4(dest.address, addr4))
        return std::nullopt;
    addr4.sin_family = AF_INET;
    addr4.sin_port = htons(dest.port);
    return make_sockaddr_result(addr4);
}

}

#endif
