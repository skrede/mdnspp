#ifndef HPP_GUARD_MDNSPP_DETAIL_ADDRESS_ENCODE_H
#define HPP_GUARD_MDNSPP_DETAIL_ADDRESS_ENCODE_H

#include "mdnspp/mdns_error.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/platform.h"

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <charconv>

namespace mdnspp::detail {

// Parses one dotted-quad octet at p and appends it to result. For octets
// 0..2 the next character must be '.', which p then moves past; for the last
// octet (i == 3) the octet must end exactly at end.
inline bool read_ipv4_octet(const char *&p, const char *end, int32_t i, std::vector<std::byte> &result)
{
    if(p >= end)
        return false;

    int32_t octet{};
    auto [ptr, ec] = std::from_chars(p, end, octet);
    if(ec != std::errc{} || octet < 0 || octet > 255)
        return false;

    result.push_back(static_cast<std::byte>(static_cast<uint8_t>(octet)));

    if(i < 3)
    {
        if(ptr >= end || *ptr != '.')
            return false;
        p = ptr + 1;
        return true;
    }
    return ptr == end;
}

// Encodes an IPv4 address string "a.b.c.d" into 4 raw bytes.
// Returns expected with mdns_error::invalid_ipv4_address on parse failure (never throws).
inline detail::expected<std::vector<std::byte>, mdnspp::mdns_error>
encode_ipv4(const std::string &addr)
{
    std::vector<std::byte> result;
    result.reserve(4);

    const char *p = addr.data();
    const char *end = p + addr.size();

    for(int32_t i = 0; i < 4; ++i)
    {
        if(!read_ipv4_octet(p, end, i, result))
            return detail::unexpected(mdnspp::mdns_error::invalid_ipv4_address);
    }
    return result;
}

// Encodes an IPv6 address string into 16 raw bytes using inet_pton.
// Returns expected with mdns_error::invalid_ipv6_address on parse failure.
inline detail::expected<std::vector<std::byte>, mdnspp::mdns_error>
encode_ipv6(const std::string &addr)
{
    uint8_t raw[16];
    if(::inet_pton(AF_INET6, addr.c_str(), raw) != 1)
        return detail::unexpected(mdnspp::mdns_error::invalid_ipv6_address);
    std::vector<std::byte> result;
    result.reserve(16);
    for(auto b : raw)
        result.push_back(static_cast<std::byte>(b));
    return result;
}

}

#endif
