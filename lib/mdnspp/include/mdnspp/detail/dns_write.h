#ifndef HPP_GUARD_MDNSPP_DNS_WRITE_H
#define HPP_GUARD_MDNSPP_DNS_WRITE_H

#include "mdnspp/mdns_error.h"
#include "mdnspp/service_info.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/platform.h"
#include "mdnspp/detail/dns_enums.h"

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <charconv>

namespace mdnspp::detail {

// Appends a complete DNS resource record to buf.
//   name  -- owner name (DNS wire format, pre-encoded)
//   rtype -- DNS record type
//   ttl   -- 32-bit TTL in seconds
//   rdata -- the raw rdata bytes
inline void append_dns_rr(std::vector<std::byte> &buf,
                          const std::vector<std::byte> &name,
                          dns_type rtype,
                          uint32_t ttl,
                          const std::vector<std::byte> &rdata,
                          bool cache_flush = false)
{
    buf.insert(buf.end(), name.begin(), name.end());
    push_u16_be(buf, std::to_underlying(rtype));
    push_u16_be(buf, cache_flush ? uint16_t{0x8001} : uint16_t{0x0001});
    push_u32_be(buf, ttl);
    push_u16_be(buf, static_cast<uint16_t>(rdata.size()));
    buf.insert(buf.end(), rdata.begin(), rdata.end());
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
        if(p >= end)
            return detail::make_unexpected(mdnspp::mdns_error::invalid_ipv4_address);

        int32_t octet{};
        auto [ptr, ec] = std::from_chars(p, end, octet);
        if(ec != std::errc{} || octet < 0 || octet > 255)
            return detail::make_unexpected(mdnspp::mdns_error::invalid_ipv4_address);

        result.push_back(static_cast<std::byte>(static_cast<uint8_t>(octet)));

        if(i < 3)
        {
            if(ptr >= end || *ptr != '.')
                return detail::make_unexpected(mdnspp::mdns_error::invalid_ipv4_address);
            p = ptr + 1;
        }
        else
        {
            if(ptr != end)
                return detail::make_unexpected(mdnspp::mdns_error::invalid_ipv4_address);
        }
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
        return detail::make_unexpected(mdnspp::mdns_error::invalid_ipv6_address);
    std::vector<std::byte> result;
    result.reserve(16);
    for(auto b : raw)
        result.push_back(static_cast<std::byte>(b));
    return result;
}

// Encodes a vector of service_txt entries as RFC 6763 TXT rdata.
// Each entry becomes a length-prefixed string of "key=value" or "key".
inline std::vector<std::byte> encode_txt_records(const std::vector<mdnspp::service_txt> &entries)
{
    std::vector<std::byte> result;
    for(const auto &entry : entries)
    {
        std::string s = entry.key;
        if(entry.value.has_value())
        {
            s += '=';
            s += *entry.value;
        }
        // Length prefix (clamped to 255 per RFC 6763)
        uint8_t len = static_cast<uint8_t>(s.size() < 255 ? s.size() : 255);
        result.push_back(static_cast<std::byte>(len));
        for(size_t i = 0; i < len; ++i)
            result.push_back(static_cast<std::byte>(static_cast<uint8_t>(s[i])));
    }
    return result;
}

// Builds an RFC 4034 section 4.1.2 window-block-0 type bitmap for NSEC records.
// Sets bits for PTR(12), TXT(16), SRV(33), and conditionally A(1) and AAAA(28)
// based on the service_info address fields. NSEC(47) is NOT set per RFC 6762 section 6.1.
// Returns the complete window block: [window=0x00][bitmap_length][bitmap bytes...].
// Trailing zero bytes are trimmed per RFC 4034 section 4.1.2.
inline std::vector<std::byte> build_nsec_bitmap(const mdnspp::service_info &info)
{
    // Highest type bit we need is SRV=33, which falls in byte index 4 (covers types 32-39).
    // Allocate 5 bytes (types 0-39).
    std::vector<uint8_t> bitmap(5, 0);

    auto set_bit = [&](uint16_t type_val)
    {
        bitmap[type_val / 8] |= static_cast<uint8_t>(1u << (7u - (type_val % 8u)));
    };

    // Always set PTR(12), TXT(16), SRV(33)
    set_bit(std::to_underlying(dns_type::ptr));  // 12
    set_bit(std::to_underlying(dns_type::txt));  // 16
    set_bit(std::to_underlying(dns_type::srv));  // 33

    // Conditionally set A(1) and AAAA(28)
    if(info.address_ipv4.has_value())
        set_bit(std::to_underlying(dns_type::a));    // 1
    if(info.address_ipv6.has_value())
        set_bit(std::to_underlying(dns_type::aaaa)); // 28

    // Trim trailing zero bytes
    while(!bitmap.empty() && bitmap.back() == 0)
        bitmap.pop_back();

    // Build window block: [window=0x00][length][bitmap bytes...]
    std::vector<std::byte> result;
    result.reserve(2 + bitmap.size());
    result.push_back(std::byte{0x00}); // window number
    result.push_back(static_cast<std::byte>(bitmap.size()));
    for(auto b : bitmap)
        result.push_back(static_cast<std::byte>(b));

    return result;
}

// Appends a complete NSEC resource record to buf.
// NSEC rdata = next domain name (same as owner for mDNS, per RFC 6762 section 6.1)
//            + type bitmap from build_nsec_bitmap.
// No cache-flush bit for NSEC records.
inline void append_nsec_rr(std::vector<std::byte> &buf,
                           const std::vector<std::byte> &owner_name,
                           const mdnspp::service_info &info,
                           uint32_t ttl)
{
    auto bitmap = build_nsec_bitmap(info);
    std::vector<std::byte> rdata;
    rdata.reserve(owner_name.size() + bitmap.size());
    rdata.insert(rdata.end(), owner_name.begin(), owner_name.end());
    rdata.insert(rdata.end(), bitmap.begin(), bitmap.end());
    append_dns_rr(buf, owner_name, dns_type::nsec, ttl, rdata);
}

}

#endif
