#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_KNOWN_ANSWER_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_KNOWN_ANSWER_H

#include "mdnspp/records.h"
#include "mdnspp/service_info.h"
#include "mdnspp/service_options.h"

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_write.h"
#include "mdnspp/detail/dns_enums.h"

#include <span>
#include <chrono>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <variant>
#include <algorithm>

namespace mdnspp::detail {

struct suppression_mask
{
    bool ptr{false};
    bool srv{false};
    bool a{false};
    bool aaaa{false};
    bool txt{false};
};

// Per-type known-answer suppression thresholds in TTL seconds. RFC 6762 §7.1:
// suppression requires the known answer's TTL to be at least half the TTL the
// responder would send — derived from the per-type TTLs actually sent.
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
        return static_cast<uint32_t>(static_cast<double>(ttl.count()) * fraction);
    };
    return ka_thresholds{
        .ptr  = th(opts.ptr_ttl),
        .srv  = th(opts.srv_ttl),
        .txt  = th(opts.txt_ttl),
        .a    = th(opts.a_ttl),
        .aaaa = th(opts.aaaa_ttl),
    };
}

// True when the parsed record asserts exactly this server's record: matching
// owner name, type-appropriate ownership, AND matching rdata (RFC 6762 §7.1).
inline bool record_matches_ours(const mdns_record_variant &rec, const service_info &info)
{
    return std::visit([&](const auto &r) -> bool
    {
        using T = std::decay_t<decltype(r)>;
        if constexpr(std::is_same_v<T, record_ptr>)
        {
            return r.name == info.service_type && r.ptr_name == info.service_name;
        }
        else if constexpr(std::is_same_v<T, record_srv>)
        {
            return r.name == info.service_name
                && r.port == info.port
                && r.weight == info.weight
                && r.priority == info.priority
                && r.srv_name == info.hostname;
        }
        else if constexpr(std::is_same_v<T, record_txt>)
        {
            if(r.name != info.service_name)
                return false;
            // An empty TXT record is a single zero-length string on the wire
            // (RFC 6763 §6.1); the parser surfaces it as one empty entry.
            // Skip empty entries on both sides so an empty TXT compares equal.
            auto is_empty = [](const service_txt &e) { return e.key.empty() && !e.value.has_value(); };
            std::size_t i = 0;
            std::size_t j = 0;
            while(true)
            {
                while(i < r.entries.size() && is_empty(r.entries[i])) ++i;
                while(j < info.txt_records.size() && is_empty(info.txt_records[j])) ++j;
                if(i == r.entries.size() || j == info.txt_records.size())
                    break;
                if(r.entries[i].key != info.txt_records[j].key
                   || r.entries[i].value != info.txt_records[j].value)
                    return false;
                ++i;
                ++j;
            }
            return i == r.entries.size() && j == info.txt_records.size();
        }
        else if constexpr(std::is_same_v<T, record_a>)
        {
            return r.name == info.hostname
                && info.address_ipv4.has_value()
                && r.address_string == *info.address_ipv4;
        }
        else if constexpr(std::is_same_v<T, record_aaaa>)
        {
            return r.name == info.hostname
                && info.address_ipv6.has_value()
                && r.address_string == *info.address_ipv6;
        }
        else
        {
            return false;
        }
    }, rec);
}

// RFC 6762 §9: a record claiming one of this server's unique names (instance
// or hostname) with DIFFERENT rdata is a conflict requiring re-probing. PTR is
// a shared record type and never conflicts.
inline bool record_conflicts_ours(const mdns_record_variant &rec, const service_info &info)
{
    return std::visit([&](const auto &r) -> bool
    {
        using T = std::decay_t<decltype(r)>;
        if constexpr(std::is_same_v<T, record_ptr>)
        {
            return false;
        }
        else if constexpr(std::is_same_v<T, record_srv> || std::is_same_v<T, record_txt>)
        {
            return r.name == info.service_name && !record_matches_ours(rec, info);
        }
        else if constexpr(std::is_same_v<T, record_a> || std::is_same_v<T, record_aaaa>)
        {
            return r.name == info.hostname && !record_matches_ours(rec, info);
        }
        else
        {
            return false;
        }
    }, rec);
}

inline void mark_suppressed_type(suppression_mask &mask, const mdns_record_variant &rec)
{
    switch(record_type(rec))
    {
    case dns_type::ptr:  mask.ptr  = true; break;
    case dns_type::srv:  mask.srv  = true; break;
    case dns_type::a:    mask.a    = true; break;
    case dns_type::aaaa: mask.aaaa = true; break;
    case dns_type::txt:  mask.txt  = true; break;
    default: break;
    }
}

// Builds a suppression mask from parsed records (TC accumulation path).
// A record suppresses only when name, type AND rdata match this server's
// record and the TTL clears the per-type threshold (RFC 6762 §7.1/§7.2).
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

// Parses the known-answer (Answer) section of a query packet starting at
// `offset` and returns the per-type suppression mask. RFC 6762 §7.1: an
// answer suppresses only when its name, type, class AND rdata match the
// record this server would send, and its TTL is at least the per-type
// threshold (half the TTL actually sent).
inline suppression_mask parse_known_answers(std::span<const std::byte> data, size_t offset,
                                            const service_info &info,
                                            const ka_thresholds &th = {})
{
    suppression_mask mask;

    if(data.size() < 12)
        return mask;

    const std::byte *buf = data.data();
    uint16_t ancount = read_u16_be(buf + 6);

    // Pre-encode our own rdata once for byte-exact comparisons.
    std::vector<std::byte> our_txt = encode_txt_records(info.txt_records);
    std::vector<std::byte> our_a;
    if(info.address_ipv4.has_value())
    {
        if(auto enc = encode_ipv4(*info.address_ipv4); enc.has_value())
            our_a = std::move(*enc);
    }
    std::vector<std::byte> our_aaaa;
    if(info.address_ipv6.has_value())
    {
        if(auto enc = encode_ipv6(*info.address_ipv6); enc.has_value())
            our_aaaa = std::move(*enc);
    }

    for(uint16_t i = 0; i < ancount; ++i)
    {
        auto name_result = read_dns_name(data, offset);
        if(!name_result.has_value())
            break;

        if(!skip_dns_name(data, offset))
            break;

        if(offset + 10 > data.size())
            break;

        dns_type rtype = static_cast<dns_type>(read_u16_be(buf + offset));
        offset += 2;
        uint16_t rclass = static_cast<uint16_t>(read_u16_be(buf + offset) & 0x7FFFu);
        offset += 2;
        uint32_t ttl = read_u32_be(buf + offset);
        offset += 4;
        uint16_t rdlength = read_u16_be(buf + offset);
        offset += 2;
        size_t rdata_offset = offset;
        offset += rdlength;

        if(offset > data.size())
            break;

        if(rclass != to_underlying(dns_class::in))
            continue;

        dns_name ans_name{*name_result};
        auto rdata = data.subspan(rdata_offset, rdlength);

        auto rdata_equals = [&](const std::vector<std::byte> &ours)
        {
            return !ours.empty() && rdlength == ours.size()
                && std::equal(rdata.begin(), rdata.end(), ours.begin());
        };

        switch(rtype)
        {
        case dns_type::ptr:
            // A PTR record is shared by owner name (the service type) across
            // every instance of that type. RFC 6762 §7.1 suppression must only
            // fire when the known answer names *this* server's instance — i.e.
            // its rdata target equals info.service_name. Without this check a
            // browse query carrying any *other* node's PTR known-answer (same
            // owner name, different target) would wrongly suppress our PTR,
            // so a live-but-silent responder never answers a peer's browse.
            if(ans_name == info.service_type && ttl >= th.ptr)
            {
                if(auto target = read_dns_name(data, rdata_offset);
                   target.has_value() && dns_name{*target} == info.service_name)
                    mask.ptr = true;
            }
            break;
        case dns_type::srv:
            if(ans_name == info.service_name && ttl >= th.srv && rdlength >= 6)
            {
                uint16_t prio = read_u16_be(buf + rdata_offset);
                uint16_t weight = read_u16_be(buf + rdata_offset + 2);
                uint16_t port = read_u16_be(buf + rdata_offset + 4);
                auto target = read_dns_name(data, rdata_offset + 6);
                if(prio == info.priority && weight == info.weight && port == info.port
                   && target.has_value() && dns_name{*target} == info.hostname)
                    mask.srv = true;
            }
            break;
        case dns_type::a:
            if(ans_name == info.hostname && ttl >= th.a && rdata_equals(our_a))
                mask.a = true;
            break;
        case dns_type::aaaa:
            if(ans_name == info.hostname && ttl >= th.aaaa && rdata_equals(our_aaaa))
                mask.aaaa = true;
            break;
        case dns_type::txt:
            if(ans_name == info.service_name && ttl >= th.txt && rdata_equals(our_txt))
                mask.txt = true;
            break;
        default: break;
        }
    }

    return mask;
}

}

#endif
