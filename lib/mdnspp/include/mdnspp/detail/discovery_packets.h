#ifndef HPP_GUARD_MDNSPP_DETAIL_DISCOVERY_PACKETS_H
#define HPP_GUARD_MDNSPP_DETAIL_DISCOVERY_PACKETS_H

#include "mdnspp/detail/dns_frame.h"
#include "mdnspp/detail/byte_order.h"

#include "mdnspp/records.h"
#include "mdnspp/dns_name.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/service_type.h"

#include <span>
#include <vector>
#include <cstddef>
#include <utility>
#include <variant>
#include <algorithm>

namespace mdnspp::detail {

// Records in query packets (QR=0) are known-answer lists or probe proposals, not answers
// (RFC 6762 section 7.1, section 8.2).
inline bool is_response_packet(std::span<const std::byte> data)
{
    return data.size() >= 12 && (read_u16_be(data.data() + 2) & 0x8000);
}

inline std::vector<mdns_record_variant> collect_records(std::span<const std::byte> data, const endpoint &sender)
{
    std::vector<mdns_record_variant> batch;
    walk_dns_frame(data, sender,
        [&batch](mdns_record_variant rec)
        {
            batch.push_back(std::move(rec));
        });
    return batch;
}

inline bool any_record_named(const std::vector<mdns_record_variant> &batch, const dns_name &name)
{
    return std::any_of(batch.begin(), batch.end(),
        [&name](const mdns_record_variant &rec)
        {
            return std::visit([&name](const auto &r)
            {
                return r.name == name;
            }, rec);
        });
}

// Returns whether rec is a PTR record of the DNS-SD meta-query name (RFC 6763 section 9), even when its
// service type is already in types.
inline bool add_enumerated_type(const mdns_record_variant &rec, std::vector<service_type_info> &types)
{
    if(auto *ptr = std::get_if<record_ptr>(&rec))
    {
        if(ptr->name == "_services._dns-sd._udp.local.")
        {
            auto info = parse_service_type(ptr->ptr_name);
            bool dup = std::any_of(types.begin(), types.end(),
                [&](const service_type_info &t)
                { return t.service_type == info.service_type; });
            if(!dup)
                types.push_back(std::move(info));
            return true;
        }
    }
    return false;
}

}

#endif
