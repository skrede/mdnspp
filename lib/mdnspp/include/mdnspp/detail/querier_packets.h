#ifndef HPP_GUARD_MDNSPP_DETAIL_QUERIER_PACKETS_H
#define HPP_GUARD_MDNSPP_DETAIL_QUERIER_PACKETS_H

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/byte_order.h"
#include "mdnspp/detail/discovery_packets.h"

#include "mdnspp/records.h"
#include "mdnspp/dns_name.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/callback_types.h"

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <iterator>

namespace mdnspp::detail {

enum class question_step
{
    stop,
    match,
    no_match,
};

inline question_step match_qm_question(std::span<const std::byte> data, std::size_t &offset, const dns_name &name,
                                       dns_type type)
{
    std::size_t name_start = offset;
    if(!skip_dns_name(data, offset))
        return question_step::stop;
    if(offset + 4 > data.size())
        return question_step::stop;

    uint16_t q_type = read_u16_be(data.data() + offset);
    offset += 2;
    uint16_t q_class = read_u16_be(data.data() + offset);
    offset += 2;

    bool is_qm = (q_class & 0x8000) == 0;
    bool type_match = q_type == to_underlying(type);

    if(type_match && is_qm)
    {
        auto incoming_name = read_dns_name(data, name_start);
        if(incoming_name.has_value() && name == dns_name{*incoming_name})
            return question_step::match;
    }
    return question_step::no_match;
}

// RFC 6762 section 7.3 permits suppression only when the observed known-answer section holds nothing we do not also
// hold; the querier holds no known answers, so only a query without answers may suppress ours.
inline bool is_duplicate_question(std::span<const std::byte> data, const dns_name &name, dns_type type)
{
    if(data.size() < 12)
        return false;

    uint16_t flags = read_u16_be(data.data() + 2);
    if(flags & 0x8000)
        return false;

    uint16_t ancount = read_u16_be(data.data() + 6);
    if(ancount != 0)
        return false;

    uint16_t qdcount = read_u16_be(data.data() + 4);
    std::size_t offset = 12;

    for(uint16_t i = 0; i < qdcount; ++i)
    {
        question_step step = match_qm_question(data, offset, name, type);
        if(step == question_step::stop)
            break;
        if(step == question_step::match)
            return true;
    }
    return false;
}

inline bool take_relevant_response(std::span<const std::byte> data, const endpoint &sender, const dns_name &name,
                                   record_callback &on_record, std::vector<mdns_record_variant> &results)
{
    if(!is_response_packet(data))
        return false;

    std::vector<mdns_record_variant> batch = collect_records(data, sender);
    bool relevant = any_record_named(batch, name);
    if(relevant)
    {
        if(on_record)
        {
            for(const auto &rec : batch)
                on_record(sender, rec);
        }
        results.insert(results.end(), std::make_move_iterator(batch.begin()), std::make_move_iterator(batch.end()));
    }
    return relevant;
}

}

#endif
