#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_META_RESPONSE_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_META_RESPONSE_H

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_write.h"
#include "mdnspp/detail/server_query_match.h"

#include "mdnspp/service_info.h"

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace mdnspp::detail {

inline void append_one_answer_header(std::vector<std::byte> &packet)
{
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, 0x8400);
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, 0x0001);
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, 0x0000);
}

inline std::vector<std::byte> build_meta_query_response(const service_info &info, uint32_t ttl = 4500)
{
    std::vector<std::byte> packet;
    append_one_answer_header(packet);
    auto owner = encode_dns_name(meta_query_name);
    auto rdata = encode_dns_name(info.service_type);
    if(!owner.has_value() || !rdata.has_value())
        return {};
    append_dns_rr(packet, *owner, dns_type::ptr, ttl, *rdata, false);
    return packet;
}

inline std::vector<std::byte> build_subtype_response(std::string_view subtype_label, const service_info &info,
                                                     uint32_t ttl = 4500)
{
    std::vector<std::byte> packet;
    append_one_answer_header(packet);
    auto subtype_name = std::string(subtype_label) + "._sub." + info.service_type.str();
    auto owner = encode_dns_name(subtype_name);
    auto rdata = encode_dns_name(info.service_name);
    if(!owner.has_value() || !rdata.has_value())
        return {};
    append_dns_rr(packet, *owner, dns_type::ptr, ttl, *rdata, false);
    return packet;
}

}

#endif
