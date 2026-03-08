#ifndef HPP_GUARD_MDNSPP_SERVER_RESPONSE_AGGREGATION_H
#define HPP_GUARD_MDNSPP_SERVER_RESPONSE_AGGREGATION_H

#include "mdnspp/service_info.h"

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_write.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_response.h"

#include "mdnspp/detail/server_query_match.h"
#include "mdnspp/detail/server_known_answer.h"

#include <vector>
#include <string>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace mdnspp::detail {

struct pending_response
{
    bool armed{false};
    dns_type qtype{dns_type::none};
    bool needs_nsec{false};
    suppression_mask suppression;

    void merge(dns_type new_qtype, bool new_nsec, const suppression_mask &new_suppression)
    {
        if(!armed)
        {
            armed = true;
            qtype = new_qtype;
            needs_nsec = new_nsec;
            suppression = new_suppression;
            return;
        }

        if(qtype != new_qtype)
            qtype = dns_type::any;

        needs_nsec = needs_nsec || new_nsec;

        // AND logic: only suppress if ALL accumulated queries suppress
        suppression.ptr = suppression.ptr && new_suppression.ptr;
        suppression.srv = suppression.srv && new_suppression.srv;
        suppression.a = suppression.a && new_suppression.a;
        suppression.aaaa = suppression.aaaa && new_suppression.aaaa;
        suppression.txt = suppression.txt && new_suppression.txt;
    }

    void reset()
    {
        armed = false;
        qtype = dns_type::none;
        needs_nsec = false;
        suppression = {};
    }
};

inline std::vector<std::byte> build_response_with_nsec(const service_info &info, dns_type qtype,
                                                       bool needs_nsec,
                                                       const suppression_mask &mask,
                                                       bool suppress_enabled)
{
    // For specific type queries, check if that type is suppressed
    if(suppress_enabled && qtype != dns_type::any)
    {
        bool suppressed = false;
        switch(qtype)
        {
        case dns_type::ptr:  suppressed = mask.ptr; break;
        case dns_type::srv:  suppressed = mask.srv; break;
        case dns_type::a:    suppressed = mask.a; break;
        case dns_type::aaaa: suppressed = mask.aaaa; break;
        case dns_type::txt:  suppressed = mask.txt; break;
        default: break;
        }
        if(suppressed)
            return {};
    }

    auto response = build_dns_response(info, qtype);

    if(needs_nsec && qtype != dns_type::any)
    {
        if(response.empty())
        {
            push_u16_be(response, 0x0000); // id
            push_u16_be(response, 0x8400); // flags
            push_u16_be(response, 0x0000); // qdcount
            push_u16_be(response, 0x0000); // ancount
            push_u16_be(response, 0x0000); // nscount
            push_u16_be(response, 0x0001); // arcount = 1

            auto owner_name = encode_dns_name(info.hostname);
            append_nsec_rr(response, owner_name, info, 4500);
        }
        else
        {
            auto owner_name = encode_dns_name(info.hostname);
            append_nsec_rr(response, owner_name, info, 4500);
            uint16_t arcount = read_u16_be(response.data() + 10);
            ++arcount;
            response[10] = static_cast<std::byte>(static_cast<uint8_t>(arcount >> 8));
            response[11] = static_cast<std::byte>(static_cast<uint8_t>(arcount & 0xFF));
        }
    }

    return response;
}

inline std::vector<std::byte> build_meta_query_response(const service_info &info)
{
    std::vector<std::byte> packet;
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, 0x8400);
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, 0x0001);
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, 0x0000);

    auto owner = encode_dns_name(meta_query_name);
    auto rdata = encode_dns_name(info.service_type);
    append_dns_rr(packet, owner, dns_type::ptr, 4500, rdata, false);

    return packet;
}

inline std::vector<std::byte> build_subtype_response(std::string_view subtype_label,
                                                     const service_info &info)
{
    std::vector<std::byte> packet;
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, 0x8400);
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, 0x0001);
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, 0x0000);

    auto subtype_name = std::string(subtype_label) + "._sub." + std::string(strip_dot(info.service_type)) + ".";
    auto owner = encode_dns_name(subtype_name);
    auto rdata = encode_dns_name(info.service_name);
    append_dns_rr(packet, owner, dns_type::ptr, 4500, rdata, false);

    return packet;
}

}

#endif
