#ifndef HPP_GUARD_MDNSPP_PARSE_H
#define HPP_GUARD_MDNSPP_PARSE_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_error.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/mdns_util.h"
#include "mdnspp/detail/parse_txt.h"

#include <span>
#include <cstddef>
#include <cstring>

namespace mdnspp {

struct record_metadata
{
    endpoint sender;
    uint32_t ttl{0};
    dns_class rclass{dns_class::none};
    dns_type rtype{dns_type::none};
    bool cache_flush{false};
    size_t name_offset{0};
    size_t record_offset{0};
    size_t record_length{0};
};

namespace parse {

inline expected<std::string, mdns_error>
extract_owner_name(std::span<const std::byte> buffer, const record_metadata &meta)
{
    auto name = detail::read_dns_name(buffer, meta.name_offset);
    if(!name)
        return detail::unexpected(mdns_error::parse_error);
    return std::move(*name);
}

template <typename Record>
inline expected<Record, mdns_error>
make_record_with_header(std::span<const std::byte> buffer, const record_metadata &meta)
{
    auto owner = extract_owner_name(buffer, meta);
    if(!owner)
        return detail::unexpected(mdns_error::parse_error);

    Record r;
    r.name = std::move(*owner);
    r.ttl = meta.ttl;
    r.rclass = meta.rclass;
    r.length = static_cast<uint32_t>(meta.record_length);
    r.sender_address = meta.sender.address;
    r.cache_flush = meta.cache_flush;
    return r;
}

// Bound the rdata name read to the record's extent. Compression pointers are
// backward-only (RFC 9267), so a prefix span keeps them resolvable while
// preventing the name from spilling into subsequent records.
inline expected<std::string, mdns_error>
read_bounded_name(std::span<const std::byte> buffer, const record_metadata &meta, size_t name_offset)
{
    return detail::read_dns_name(buffer.first(meta.record_offset + meta.record_length), name_offset);
}

inline expected<mdns_record_variant, mdns_error>
a(std::span<const std::byte> buffer, const record_metadata &meta)
{
    if(buffer.size() < meta.record_offset + meta.record_length)
        return detail::unexpected(mdns_error::parse_error);

    if(meta.record_length != 4)
        return detail::unexpected(mdns_error::parse_error);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    std::memcpy(&addr.sin_addr.s_addr, buffer.data() + meta.record_offset, 4);

    auto r = make_record_with_header<record_a>(buffer, meta);
    if(!r)
        return detail::unexpected(mdns_error::parse_error);
    r->address_string = detail::ip_address_to_string(addr);

    return std::move(*r);
}

inline expected<mdns_record_variant, mdns_error>
aaaa(std::span<const std::byte> buffer, const record_metadata &meta)
{
    if(buffer.size() < meta.record_offset + meta.record_length)
        return detail::unexpected(mdns_error::parse_error);

    if(meta.record_length != 16)
        return detail::unexpected(mdns_error::parse_error);

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    std::memcpy(&addr.sin6_addr, buffer.data() + meta.record_offset, 16);

    auto r = make_record_with_header<record_aaaa>(buffer, meta);
    if(!r)
        return detail::unexpected(mdns_error::parse_error);
    r->address_string = detail::ip_address_to_string(addr);

    return std::move(*r);
}

inline expected<mdns_record_variant, mdns_error>
ptr(std::span<const std::byte> buffer, const record_metadata &meta)
{
    if(buffer.size() < meta.record_offset + meta.record_length)
        return detail::unexpected(mdns_error::parse_error);

    auto ptr_name = read_bounded_name(buffer, meta, meta.record_offset);
    if(!ptr_name) return detail::unexpected(mdns_error::parse_error);

    auto r = make_record_with_header<record_ptr>(buffer, meta);
    if(!r)
        return detail::unexpected(mdns_error::parse_error);
    r->ptr_name = std::move(*ptr_name);

    return std::move(*r);
}

inline expected<mdns_record_variant, mdns_error>
srv(std::span<const std::byte> buffer, const record_metadata &meta)
{
    if(buffer.size() < meta.record_offset + meta.record_length)
        return detail::unexpected(mdns_error::parse_error);

    if(meta.record_length < 7)
        return detail::unexpected(mdns_error::parse_error);

    const std::byte *rdata = buffer.data() + meta.record_offset;
    uint16_t priority = detail::read_u16_be(rdata + 0);
    uint16_t weight = detail::read_u16_be(rdata + 2);
    uint16_t port = detail::read_u16_be(rdata + 4);

    auto srv_name = read_bounded_name(buffer, meta, meta.record_offset + 6);
    if(!srv_name) return detail::unexpected(mdns_error::parse_error);

    auto r = make_record_with_header<record_srv>(buffer, meta);
    if(!r)
        return detail::unexpected(mdns_error::parse_error);
    r->priority = priority;
    r->weight = weight;
    r->port = port;
    r->srv_name = std::move(*srv_name);

    return std::move(*r);
}

inline expected<mdns_record_variant, mdns_error>
txt(std::span<const std::byte> buffer, const record_metadata &meta)
{
    if(buffer.size() < meta.record_offset + meta.record_length)
        return detail::unexpected(mdns_error::parse_error);

    auto r = make_record_with_header<record_txt>(buffer, meta);
    if(!r)
        return detail::unexpected(mdns_error::parse_error);
    r->entries = parse_txt_entries(buffer, meta.record_offset, meta.record_offset + meta.record_length);

    return std::move(*r);
}

inline expected<mdns_record_variant, mdns_error>
record(std::span<const std::byte> buffer, const record_metadata &meta)
{
    switch(meta.rtype)
    {
    case dns_type::a: return a(buffer, meta);
    case dns_type::ptr: return ptr(buffer, meta);
    case dns_type::txt: return txt(buffer, meta);
    case dns_type::aaaa: return aaaa(buffer, meta);
    case dns_type::srv: return srv(buffer, meta);
    default: return detail::unexpected(mdns_error::parse_error);
    }
}

}

}

#endif
