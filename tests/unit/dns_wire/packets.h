#ifndef HPP_GUARD_MDNSPP_DNS_WIRE_PACKETS_H
#define HPP_GUARD_MDNSPP_DNS_WIRE_PACKETS_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/service_info.h"

#include "mdnspp/detail/dns_wire.h"

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <optional>
#include <string_view>

inline mdnspp::service_info make_test_service_v46()
{
    mdnspp::service_info info;
    info.service_name = "MyService._http._tcp.local.";
    info.service_type = "_http._tcp.local.";
    info.hostname = "myhost.local.";
    info.port = 8080;
    info.priority = 0;
    info.weight = 0;
    info.address_ipv4 = "192.168.1.10";
    info.address_ipv6 = "::1";
    info.txt_records = {mdnspp::service_txt{"path", "/api"}, mdnspp::service_txt{"ver", std::nullopt}};
    return info;
}

inline mdnspp::record_ptr make_ptr_record(std::string_view name, std::string_view ptr_name)
{
    mdnspp::record_ptr ptr;
    ptr.name = name;
    ptr.ttl = 4500;
    ptr.ptr_name = ptr_name;
    return ptr;
}

inline std::vector<mdnspp::mdns_record_variant> parse_wire(const std::vector<std::byte> &pkt)
{
    std::vector<mdnspp::mdns_record_variant> records;
    mdnspp::detail::walk_dns_frame(std::span<const std::byte>(pkt), mdnspp::endpoint{},
                                   [&](mdnspp::mdns_record_variant rv)
                                   {
                                       records.push_back(std::move(rv));
                                   });
    return records;
}

inline void skip_question_section(std::span<const std::byte> pkt, std::size_t &offset)
{
    uint16_t qdcount = mdnspp::detail::read_u16_be(pkt.data() + 4);
    for(uint16_t i = 0; i < qdcount; ++i)
    {
        mdnspp::detail::skip_dns_name(pkt, offset);
        offset += 4;
    }
}

inline std::pair<uint16_t, uint16_t> read_rr_type_class(std::span<const std::byte> pkt, std::size_t &offset)
{
    mdnspp::detail::skip_dns_name(pkt, offset);
    uint16_t rtype = mdnspp::detail::read_u16_be(pkt.data() + offset);
    uint16_t rclass = mdnspp::detail::read_u16_be(pkt.data() + offset + 2);
    uint16_t rdlength = mdnspp::detail::read_u16_be(pkt.data() + offset + 8);
    offset += 10 + rdlength;
    return {rtype, rclass};
}

inline std::vector<std::pair<uint16_t, uint16_t>> collect_rr_type_class(const std::vector<std::byte> &pkt)
{
    std::vector<std::pair<uint16_t, uint16_t>> result;
    auto span = std::span<const std::byte>(pkt);
    std::size_t offset = 12;
    skip_question_section(span, offset);
    uint32_t rr_total = static_cast<uint32_t>(mdnspp::detail::read_u16_be(pkt.data() + 6)) +
        static_cast<uint32_t>(mdnspp::detail::read_u16_be(pkt.data() + 8)) +
        static_cast<uint32_t>(mdnspp::detail::read_u16_be(pkt.data() + 10));
    for(uint32_t rr = 0; rr < rr_total; ++rr)
        result.push_back(read_rr_type_class(span, offset));
    return result;
}

#endif
