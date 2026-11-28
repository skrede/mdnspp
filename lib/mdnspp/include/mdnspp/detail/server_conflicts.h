#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_CONFLICTS_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_CONFLICTS_H

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_frame.h"
#include "mdnspp/detail/dns_query.h"
#include "mdnspp/detail/byte_order.h"
#include "mdnspp/detail/sibling_records.h"
#include "mdnspp/detail/server_record_match.h"
#include "mdnspp/detail/server_probe_announce.h"

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/service_info.h"

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <variant>

namespace mdnspp::detail {

enum class probe_verdict : uint8_t
{
    none,
    conflict,
    deferred,
};

// RFC 6762 section 8.1: while probing, any record named like our instance or hostname is a conflict, unless
// another server of our group publishes it (section 14).
inline bool response_conflicts(std::span<const std::byte> data, const service_info &info,
                               const sibling_membership &siblings)
{
    bool conflict = false;
    walk_dns_frame(data, endpoint{}, [&](mdns_record_variant rv)
    {
        if(siblings.owns(rv))
            return;
        std::visit([&](const auto &rec)
        {
            if(rec.name == info.service_name || rec.name == info.hostname)
                conflict = true;
        }, rv);
    });
    return conflict;
}

inline std::vector<tiebreak_record> our_tiebreak_records(const service_info &info)
{
    std::vector<tiebreak_record> records;
    for(auto &rec : build_proposed_records(info))
        records.push_back(tiebreak_record{to_underlying(dns_class::in), to_underlying(rec.rtype),
                                          std::move(rec.rdata)});
    return records;
}

// RFC 6762 section 8.2.1 tiebreaking over the full proposed record sets, compared in DNS uncompressed
// form ordered by class, type, rdata. Our own looped-back probe carries an identical record set and
// compares equal: an exact tie is not a conflict.
inline probe_verdict tiebreak(std::span<const std::byte> probe, const service_info &info)
{
    auto theirs = extract_authority_records(probe);
    if(theirs.empty())
        return probe_verdict::conflict;
    if(compare_record_sets(our_tiebreak_records(info), std::move(theirs)) < 0)
        return probe_verdict::deferred;
    return probe_verdict::none;
}

// A response is checked against RFC 6762 section 8.1; a query carrying an authority section is a
// simultaneous probe (section 8.2).
inline probe_verdict classify_probing_packet(std::span<const std::byte> data, const service_info &info,
                                             const sibling_membership &siblings)
{
    if(data.size() < 12)
        return probe_verdict::none;

    uint16_t flags = read_u16_be(data.data() + 2);
    if(flags & 0x8000)
        return response_conflicts(data, info, siblings) ? probe_verdict::conflict : probe_verdict::none;

    uint16_t nscount = read_u16_be(data.data() + 8);
    if(nscount == 0 || !response_conflicts(data, info, siblings))
        return probe_verdict::none;
    return tiebreak(data, info);
}

// RFC 6762 section 9: while announcing or live, a record with our unique name and different rdata that no other
// server of our group publishes (section 14).
inline bool live_conflict(const std::vector<mdns_record_variant> &records, const service_info &info,
                          const sibling_membership &siblings)
{
    for(const auto &rec : records)
    {
        if(record_conflicts_ours(rec, info) && !siblings.owns(rec))
            return true;
    }
    return false;
}

}

#endif
