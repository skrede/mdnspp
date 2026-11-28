#ifndef HPP_GUARD_MDNSPP_SERVER_DETAIL_HELPERS_H
#define HPP_GUARD_MDNSPP_SERVER_DETAIL_HELPERS_H

#include "mdnspp/records.h"
#include "mdnspp/service_info.h"
#include "mdnspp/service_options.h"

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_write.h"
#include "mdnspp/detail/byte_order.h"
#include "mdnspp/detail/server_query_match.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <optional>
#include <string_view>
#include <initializer_list>

using namespace mdnspp;
using namespace mdnspp::detail;

inline service_info make_test_info()
{
    service_info info;
    info.service_name = "MyApp._http._tcp.local.";
    info.service_type = "_http._tcp.local.";
    info.hostname = "myhost.local.";
    info.port = 8080;
    info.address_ipv4 = "192.168.1.10";
    info.address_ipv6 = std::nullopt;
    return info;
}

inline service_info make_subtype_test_info()
{
    auto info = make_test_info();
    info.subtypes = {"_printer"};
    return info;
}

inline record_ptr make_ptr(std::string_view name, std::string_view ptr_name, uint32_t ttl = 0)
{
    record_ptr ptr;
    ptr.name = name;
    ptr.ttl = ttl;
    ptr.ptr_name = ptr_name;
    return ptr;
}

inline record_srv make_srv(std::string_view name, uint16_t port, std::string_view target, uint32_t ttl = 0)
{
    record_srv srv;
    srv.name = name;
    srv.ttl = ttl;
    srv.port = port;
    srv.srv_name = target;
    return srv;
}

inline record_a make_a(std::string_view name, std::string_view address, uint32_t ttl = 0)
{
    record_a a;
    a.name = name;
    a.ttl = ttl;
    a.address_string = address;
    return a;
}

inline std::vector<std::byte> wire_name(std::string_view name)
{
    return encode_dns_name(name).value();
}

inline void push_header(std::vector<std::byte> &pkt, uint16_t qdcount, uint16_t ancount)
{
    push_u16_be(pkt, 0x0000); // id
    push_u16_be(pkt, 0x0000); // flags (query)
    push_u16_be(pkt, qdcount);
    push_u16_be(pkt, ancount);
    push_u16_be(pkt, 0x0000); // nscount
    push_u16_be(pkt, 0x0000); // arcount
}

inline void push_question(std::vector<std::byte> &pkt, std::string_view qname, dns_type qtype, bool qu_bit)
{
    auto encoded = wire_name(qname);
    pkt.insert(pkt.end(), encoded.begin(), encoded.end());
    push_u16_be(pkt, to_underlying(qtype));
    uint16_t qclass = 0x0001; // IN
    if(qu_bit)
        qclass |= 0x8000;
    push_u16_be(pkt, qclass);
}

inline std::vector<std::byte> build_multi_query_packet(
    std::initializer_list<std::pair<std::string_view, dns_type>> questions,
    bool qu_bit = false)
{
    std::vector<std::byte> pkt;
    push_header(pkt, static_cast<uint16_t>(questions.size()), 0);
    for(const auto &[name, qtype] : questions)
        push_question(pkt, name, qtype, qu_bit);
    return pkt;
}

inline std::vector<std::byte> build_query_packet(std::string_view qname, dns_type qtype, bool qu_bit = false)
{
    return build_multi_query_packet({{qname, qtype}}, qu_bit);
}

inline query_match_result match_one(std::string_view qname, dns_type qtype, const service_info &info,
                                    const service_options &opts, bool qu_bit = false)
{
    auto pkt = build_query_packet(qname, qtype, qu_bit);
    return match_queries(std::span(pkt), info, opts);
}

inline void check_pair(const question_match &match, owned_name target, dns_type qtype)
{
    CHECK(match.target == target);
    CHECK(match.qtype == qtype);
}

// RFC 6762 section 7.1 suppression matches name, type, class and rdata, so the answers carry real rdata.
struct answer_spec
{
    std::string_view name;
    dns_type rtype;
    uint32_t ttl;
    std::vector<std::byte> rdata;
};

inline std::vector<std::byte> srv_rdata(uint16_t priority, uint16_t weight, uint16_t port, std::string_view target)
{
    std::vector<std::byte> rdata;
    push_u16_be(rdata, priority);
    push_u16_be(rdata, weight);
    push_u16_be(rdata, port);
    auto encoded = wire_name(target);
    rdata.insert(rdata.end(), encoded.begin(), encoded.end());
    return rdata;
}

inline std::vector<std::byte> a_rdata(const std::string &addr)
{
    return *encode_ipv4(addr);
}

inline void push_answer(std::vector<std::byte> &pkt, const answer_spec &a)
{
    auto encoded_name = wire_name(a.name);
    pkt.insert(pkt.end(), encoded_name.begin(), encoded_name.end());
    push_u16_be(pkt, to_underlying(a.rtype));
    push_u16_be(pkt, 0x0001); // class IN
    push_u32_be(pkt, a.ttl);
    push_u16_be(pkt, static_cast<uint16_t>(a.rdata.size()));
    pkt.insert(pkt.end(), a.rdata.begin(), a.rdata.end());
}

inline std::vector<std::byte> build_answer_packet(std::initializer_list<answer_spec> answers, std::size_t &offset_out)
{
    std::vector<std::byte> pkt;
    push_header(pkt, 1, static_cast<uint16_t>(answers.size()));
    push_question(pkt, "_http._tcp.local.", dns_type::ptr, false);
    offset_out = pkt.size();
    for(const auto &a : answers)
        push_answer(pkt, a);
    return pkt;
}

#endif
