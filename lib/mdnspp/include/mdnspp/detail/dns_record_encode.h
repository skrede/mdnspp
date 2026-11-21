#ifndef HPP_GUARD_MDNSPP_DETAIL_DNS_RECORD_ENCODE_H
#define HPP_GUARD_MDNSPP_DETAIL_DNS_RECORD_ENCODE_H

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_write.h"

#include "mdnspp/records.h"

#include <vector>
#include <cstddef>
#include <cstdint>
#include <variant>

namespace mdnspp::detail {

inline std::vector<std::byte> encode_srv_rdata(uint16_t priority, uint16_t weight, uint16_t port,
                                               const std::vector<std::byte> &target)
{
    std::vector<std::byte> rdata;
    push_u16_be(rdata, priority);
    push_u16_be(rdata, weight);
    push_u16_be(rdata, port);
    rdata.insert(rdata.end(), target.begin(), target.end());
    return rdata;
}

inline void append_record_rr(std::vector<std::byte> &buf, const std::vector<std::byte> &name, const record_ptr &r)
{
    auto rdata = encode_dns_name(r.ptr_name);
    if(rdata.has_value())
        append_dns_rr(buf, name, dns_type::ptr, r.ttl, *rdata);
}

inline void append_record_rr(std::vector<std::byte> &buf, const std::vector<std::byte> &name, const record_srv &r)
{
    auto target = encode_dns_name(r.srv_name);
    if(!target.has_value())
        return;
    append_dns_rr(buf, name, dns_type::srv, r.ttl, encode_srv_rdata(r.priority, r.weight, r.port, *target));
}

inline void append_record_rr(std::vector<std::byte> &buf, const std::vector<std::byte> &name, const record_a &r)
{
    auto enc = encode_ipv4(r.address_string);
    if(enc.has_value())
        append_dns_rr(buf, name, dns_type::a, r.ttl, *enc);
}

inline void append_record_rr(std::vector<std::byte> &buf, const std::vector<std::byte> &name, const record_aaaa &r)
{
    auto enc = encode_ipv6(r.address_string);
    if(enc.has_value())
        append_dns_rr(buf, name, dns_type::aaaa, r.ttl, *enc);
}

inline void append_record_rr(std::vector<std::byte> &buf, const std::vector<std::byte> &name, const record_txt &r)
{
    append_dns_rr(buf, name, dns_type::txt, r.ttl, encode_txt_records(r.entries));
}

// Known-answer suppression, RFC 6762 section 7.1: no cache-flush bit. A record that fails to encode is omitted, so
// the packet stays valid and the caller counts appended records only; records decoded from the wire always re-encode.
inline void append_known_answer(std::vector<std::byte> &buf, const mdns_record_variant &rec)
{
    std::visit([&buf](const auto &r)
    {
        auto name = encode_dns_name(r.name);
        if(name.has_value())
            append_record_rr(buf, *name, r);
    }, rec);
}

}

#endif
