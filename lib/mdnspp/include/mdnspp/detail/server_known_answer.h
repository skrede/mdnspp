#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_KNOWN_ANSWER_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_KNOWN_ANSWER_H

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_write.h"
#include "mdnspp/detail/server_record_match.h"
#include "mdnspp/detail/server_known_answer_record.h"

#include "mdnspp/records.h"
#include "mdnspp/service_info.h"
#include "mdnspp/service_options.h"

#include <span>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <variant>

namespace mdnspp::detail {

struct suppression_mask
{
    bool ptr{false};
    bool srv{false};
    bool a{false};
    bool aaaa{false};
    bool txt{false};
};

// RFC 6762 section 7.1: a known answer suppresses only with at least half the TTL the responder would send, so the
// thresholds derive from the per-type TTLs actually sent.
struct ka_thresholds
{
    uint32_t ptr{2250};
    uint32_t srv{60};
    uint32_t txt{2250};
    uint32_t a{60};
    uint32_t aaaa{60};
};

inline ka_thresholds make_ka_thresholds(const service_options &opts, double fraction)
{
    auto th = [fraction](std::chrono::seconds ttl) -> uint32_t {
        return static_cast<uint32_t>(static_cast<double>(wire_ttl(ttl)) * fraction);
    };
    return ka_thresholds{
        .ptr  = th(opts.ptr_ttl),
        .srv  = th(opts.srv_ttl),
        .txt  = th(opts.txt_ttl),
        .a    = th(opts.a_ttl),
        .aaaa = th(opts.aaaa_ttl),
    };
}

inline void mark_suppressed_type(suppression_mask &mask, dns_type rtype)
{
    switch(rtype)
    {
    case dns_type::ptr:  mask.ptr  = true; break;
    case dns_type::srv:  mask.srv  = true; break;
    case dns_type::a:    mask.a    = true; break;
    case dns_type::aaaa: mask.aaaa = true; break;
    case dns_type::txt:  mask.txt  = true; break;
    default: break;
    }
}

inline void mark_suppressed_type(suppression_mask &mask, const mdns_record_variant &rec)
{
    mark_suppressed_type(mask, record_type(rec));
}

// The TC accumulation path (RFC 6762 sections 7.1, 7.2): a record suppresses only when it is ours and its TTL
// clears the per-type threshold.
inline suppression_mask suppress_from_records(std::span<const mdns_record_variant> records,
                                              const service_info &info,
                                              const ka_thresholds &th)
{
    suppression_mask mask;
    for(const auto &rec : records)
    {
        if(!record_matches_ours(rec, info))
            continue;
        uint32_t ttl = std::visit([](const auto &r) { return r.ttl; }, rec);
        uint32_t threshold = [&]
        {
            switch(record_type(rec))
            {
            case dns_type::ptr:  return th.ptr;
            case dns_type::srv:  return th.srv;
            case dns_type::a:    return th.a;
            case dns_type::aaaa: return th.aaaa;
            default:             return th.txt;
            }
        }();
        if(ttl >= threshold)
            mark_suppressed_type(mask, rec);
    }
    return mask;
}

// A PTR is shared by every instance of a service type, so it suppresses ours only when its target is this
// instance; otherwise a browse carrying another node's PTR would silence a live responder (RFC 6762 section 7.1).
inline bool ptr_answer_matches(std::span<const std::byte> data, const dns_name &name, const known_answer &ka,
                               const service_info &info, const ka_thresholds &th)
{
    if(name == info.service_type && ka.ttl >= th.ptr)
    {
        auto target = read_dns_name(data, ka.rdata_offset);
        return target.has_value() && dns_name{*target} == info.service_name;
    }
    return false;
}

inline bool srv_answer_matches(std::span<const std::byte> data, const dns_name &name, const known_answer &ka,
                               const service_info &info, const ka_thresholds &th)
{
    if(name == info.service_name && ka.ttl >= th.srv && ka.rdlength >= 6)
    {
        const std::byte *rdata = data.data() + ka.rdata_offset;
        uint16_t prio = read_u16_be(rdata);
        uint16_t weight = read_u16_be(rdata + 2);
        uint16_t port = read_u16_be(rdata + 4);
        auto target = read_dns_name(data, ka.rdata_offset + 6);
        return prio == info.priority && weight == info.weight && port == info.port
            && target.has_value() && dns_name{*target} == info.hostname;
    }
    return false;
}

inline bool known_answer_matches(std::span<const std::byte> data, const known_answer &ka, const own_rdata &ours,
                                 const service_info &info, const ka_thresholds &th)
{
    dns_name name{ka.name};
    auto rdata = data.subspan(ka.rdata_offset, ka.rdlength);
    switch(ka.rtype)
    {
    case dns_type::ptr:  return ptr_answer_matches(data, name, ka, info, th);
    case dns_type::srv:  return srv_answer_matches(data, name, ka, info, th);
    case dns_type::a:    return name == info.hostname && ka.ttl >= th.a && rdata_equals(rdata, ours.a);
    case dns_type::aaaa: return name == info.hostname && ka.ttl >= th.aaaa && rdata_equals(rdata, ours.aaaa);
    case dns_type::txt:  return name == info.service_name && ka.ttl >= th.txt && rdata_equals(rdata, ours.txt);
    default:             return false;
    }
}

// The known-answer (Answer) section starts at offset; an answer suppresses when its name, type, class and rdata
// match our record and its TTL clears the per-type threshold (RFC 6762 section 7.1).
inline suppression_mask parse_known_answers(std::span<const std::byte> data, size_t offset,
                                            const service_info &info,
                                            const ka_thresholds &th = {})
{
    suppression_mask mask;
    if(data.size() < 12)
        return mask;
    uint16_t ancount = read_u16_be(data.data() + 6);
    own_rdata ours = encode_own_rdata(info);
    for(uint16_t i = 0; i < ancount; ++i)
    {
        auto ka = read_known_answer(data, offset);
        if(!ka.has_value())
            break;
        if(ka->rclass != to_underlying(dns_class::in))
            continue;
        if(known_answer_matches(data, *ka, ours, info, th))
            mark_suppressed_type(mask, ka->rtype);
    }
    return mask;
}

}

#endif
