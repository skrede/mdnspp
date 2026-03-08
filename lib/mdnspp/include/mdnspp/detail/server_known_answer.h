#ifndef HPP_GUARD_MDNSPP_SERVER_KNOWN_ANSWER_H
#define HPP_GUARD_MDNSPP_SERVER_KNOWN_ANSWER_H

#include "mdnspp/service_info.h"

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"

#include "mdnspp/detail/server_query_match.h"

#include <span>
#include <cstddef>
#include <cstdint>

namespace mdnspp::detail {

struct suppression_mask
{
    bool ptr{false};
    bool srv{false};
    bool a{false};
    bool aaaa{false};
    bool txt{false};
};

inline suppression_mask parse_known_answers(std::span<const std::byte> data, size_t offset,
                                            const service_info &info,
                                            uint32_t threshold = 2250)
{
    suppression_mask mask;

    if(data.size() < 12)
        return mask;

    const std::byte *buf = data.data();
    uint16_t ancount = read_u16_be(buf + 6);

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
        offset += 2; // rclass
        uint32_t ttl = read_u32_be(buf + offset);
        offset += 4;
        uint16_t rdlength = read_u16_be(buf + offset);
        offset += 2;
        offset += rdlength;

        if(offset > data.size())
            break;

        auto sn = strip_dot(info.service_name);
        auto st = strip_dot(info.service_type);
        auto hn = strip_dot(info.hostname);
        const auto &ans_name = *name_result;

        bool name_matches = (ans_name == sn || ans_name == st || ans_name == hn);
        if(name_matches && ttl >= threshold)
        {
            switch(rtype)
            {
            case dns_type::ptr:  mask.ptr = true; break;
            case dns_type::srv:  mask.srv = true; break;
            case dns_type::a:    mask.a = true; break;
            case dns_type::aaaa: mask.aaaa = true; break;
            case dns_type::txt:  mask.txt = true; break;
            default: break;
            }
        }
    }

    return mask;
}

inline bool all_suppressed(const suppression_mask &mask, dns_type accumulated_qtype,
                           const service_info &info)
{
    bool any_would_send = false;

    bool would_send_ptr = (accumulated_qtype == dns_type::ptr || accumulated_qtype == dns_type::any);
    bool would_send_srv = (accumulated_qtype == dns_type::srv || accumulated_qtype == dns_type::any);
    bool would_send_a = (accumulated_qtype == dns_type::a || accumulated_qtype == dns_type::any) && info.address_ipv4.has_value();
    bool would_send_aaaa = (accumulated_qtype == dns_type::aaaa || accumulated_qtype == dns_type::any) && info.address_ipv6.has_value();
    bool would_send_txt = (accumulated_qtype == dns_type::txt || accumulated_qtype == dns_type::any);

    if(would_send_ptr) { any_would_send = true; if(!mask.ptr) return false; }
    if(would_send_srv) { any_would_send = true; if(!mask.srv) return false; }
    if(would_send_a) { any_would_send = true; if(!mask.a) return false; }
    if(would_send_aaaa) { any_would_send = true; if(!mask.aaaa) return false; }
    if(would_send_txt) { any_would_send = true; if(!mask.txt) return false; }

    return any_would_send;
}

}

#endif
