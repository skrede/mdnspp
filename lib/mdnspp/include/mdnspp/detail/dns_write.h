#ifndef HPP_GUARD_MDNSPP_DETAIL_DNS_WRITE_H
#define HPP_GUARD_MDNSPP_DETAIL_DNS_WRITE_H

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/address_encode.h"

#include "mdnspp/mdns_error.h"
#include "mdnspp/service_info.h"

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace mdnspp::detail {

// Callers resolve name-encoding failures first; the guard only protects packet structure against an empty owner
// name or rdata over the uint16_t RDLENGTH limit.
inline void append_dns_rr(std::vector<std::byte> &buf,
                          const std::vector<std::byte> &name,
                          dns_type rtype,
                          uint32_t ttl,
                          const std::vector<std::byte> &rdata,
                          bool cache_flush = false)
{
    if(name.empty() || rdata.size() > UINT16_MAX)
        return;
    buf.insert(buf.end(), name.begin(), name.end());
    push_u16_be(buf, detail::to_underlying(rtype));
    push_u16_be(buf, cache_flush ? uint16_t{0x8001} : uint16_t{0x0001});
    push_u32_be(buf, ttl);
    push_u16_be(buf, static_cast<uint16_t>(rdata.size()));
    buf.insert(buf.end(), rdata.begin(), rdata.end());
}

// RFC 6763 §6.1: an entry over 255 bytes is skipped, and an empty TXT record is one zero-length string, never
// RDLENGTH 0.
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
        if(s.size() > 255)
            continue;
        auto len = static_cast<uint8_t>(s.size());
        result.push_back(static_cast<std::byte>(len));
        for(size_t i = 0; i < len; ++i)
            result.push_back(static_cast<std::byte>(static_cast<uint8_t>(s[i])));
    }
    if(result.empty())
        result.push_back(std::byte{0x00});
    return result;
}

enum class nsec_owner : uint8_t
{
    service_type,
    service_name,
    hostname,
};

inline void set_owner_type_bits(std::vector<uint8_t> &bitmap, nsec_owner owner, const mdnspp::service_info &info)
{
    auto set_bit = [&](uint16_t type_val)
    {
        bitmap[type_val / 8] |= static_cast<uint8_t>(1u << (7u - (type_val % 8u)));
    };

    switch(owner)
    {
    case nsec_owner::service_type:
        set_bit(detail::to_underlying(dns_type::ptr));
        break;
    case nsec_owner::service_name:
        set_bit(detail::to_underlying(dns_type::txt));
        set_bit(detail::to_underlying(dns_type::srv));
        set_bit(detail::to_underlying(dns_type::nsec));
        break;
    case nsec_owner::hostname:
        if(info.address_ipv4.has_value())
            set_bit(detail::to_underlying(dns_type::a));
        if(info.address_ipv6.has_value())
            set_bit(detail::to_underlying(dns_type::aaaa));
        break;
    }
}

// RFC 4034 section 4.1.2 window block 0 with trailing zero bytes trimmed. RFC 6762 section 6.1: the bitmap lists the
// types that do exist at the owner name.
inline std::vector<std::byte> build_nsec_bitmap(nsec_owner owner, const mdnspp::service_info &info)
{
    // Highest type bit needed is NSEC=47, which falls in byte index 5 (types 40-47).
    std::vector<uint8_t> bitmap(6, 0);
    set_owner_type_bits(bitmap, owner, info);

    while(!bitmap.empty() && bitmap.back() == 0)
        bitmap.pop_back();

    if(bitmap.empty())
        return {};

    std::vector<std::byte> result;
    result.reserve(2 + bitmap.size());
    result.push_back(std::byte{0x00}); // window number
    result.push_back(static_cast<std::byte>(bitmap.size()));
    for(auto b : bitmap)
        result.push_back(static_cast<std::byte>(b));

    return result;
}

// RFC 6762 section 6.1: the next domain name is the owner name itself. Skipped when no types exist at the owner.
inline void append_nsec_rr(std::vector<std::byte> &buf,
                           const std::vector<std::byte> &owner_name,
                           nsec_owner owner,
                           const mdnspp::service_info &info,
                           uint32_t ttl)
{
    auto bitmap = build_nsec_bitmap(owner, info);
    if(bitmap.empty())
        return;
    std::vector<std::byte> rdata;
    rdata.reserve(owner_name.size() + bitmap.size());
    rdata.insert(rdata.end(), owner_name.begin(), owner_name.end());
    rdata.insert(rdata.end(), bitmap.begin(), bitmap.end());
    append_dns_rr(buf, owner_name, dns_type::nsec, ttl, rdata);
}

}

#endif
