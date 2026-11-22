#ifndef HPP_GUARD_MDNSPP_DETAIL_DNS_QUERY_TC_H
#define HPP_GUARD_MDNSPP_DETAIL_DNS_QUERY_TC_H

#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_query.h"
#include "mdnspp/detail/dns_record_encode.h"

#include "mdnspp/records.h"

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <string_view>

namespace mdnspp::detail {

struct encoded_known_answers
{
    std::vector<std::byte> bytes;
    std::vector<std::pair<std::size_t, std::size_t>> bounds;
};

inline encoded_known_answers encode_known_answers(std::span<const mdns_record_variant> known_answers)
{
    encoded_known_answers out;
    for(const auto &ka : known_answers)
    {
        std::size_t before = out.bytes.size();
        append_known_answer(out.bytes, ka);
        out.bounds.emplace_back(before, out.bytes.size());
    }
    return out;
}

// A packet always takes at least one answer, so an answer larger than max_payload cannot loop forever.
inline bool needs_continuation(const std::vector<std::byte> &packet, uint16_t ancount, std::size_t answer_size,
                               std::size_t max_payload)
{
    return ancount > 0 && packet.size() + answer_size > max_payload;
}

// RFC 6762 section 7.2: the full packet gets the TC bit and its ancount; the continuation carries no questions.
inline void start_continuation(std::vector<std::vector<std::byte>> &packets, std::vector<std::byte> &current,
                               uint16_t &ancount)
{
    current[2] = static_cast<std::byte>(std::to_integer<uint8_t>(current[2]) | 0x02u);
    set_ancount(current, ancount);
    packets.push_back(std::move(current));
    current.clear();
    append_query_header(current, 0, 0);
    ancount = 0;
}

// Known answers split across TC continuation packets (RFC 6762 section 7.2); the last packet has no TC bit.
inline std::vector<std::vector<std::byte>>
build_dns_query_tc(std::string_view name, dns_type qtype,
                   std::span<const mdns_record_variant> known_answers,
                   std::size_t max_payload = 1472,
                   response_mode mode = response_mode::multicast)
{
    std::vector<std::vector<std::byte>> result;
    auto current_pkt = build_dns_query(name, qtype, mode);
    if(current_pkt.empty())
        return result;
    auto answers = encode_known_answers(known_answers);
    uint16_t current_ancount = 0;
    for(const auto &[start, end] : answers.bounds)
    {
        if(start == end)
            continue;
        if(needs_continuation(current_pkt, current_ancount, end - start, max_payload))
            start_continuation(result, current_pkt, current_ancount);
        current_pkt.insert(current_pkt.end(), answers.bytes.data() + start, answers.bytes.data() + end);
        ++current_ancount;
    }
    set_ancount(current_pkt, current_ancount);
    result.push_back(std::move(current_pkt));
    return result;
}

}

#endif
