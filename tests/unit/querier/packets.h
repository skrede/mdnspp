#ifndef HPP_GUARD_MDNSPP_QUERIER_PACKETS_H
#define HPP_GUARD_MDNSPP_QUERIER_PACKETS_H

#include "support/wire_bytes.h"

#include <array>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <string_view>

using mdnspp::test_support::bytes;
using mdnspp::test_support::push_u16_be;
using mdnspp::test_support::push_u32_be;
using mdnspp::test_support::encode_name;

inline void append(std::vector<std::byte> &pkt, const std::vector<std::byte> &tail)
{
    pkt.insert(pkt.end(), tail.begin(), tail.end());
}

inline void push_header(std::vector<std::byte> &pkt, uint16_t flags, uint16_t qdcount, uint16_t ancount)
{
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, flags);
    push_u16_be(pkt, qdcount);
    push_u16_be(pkt, ancount);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0000);
}

inline void push_record_header(std::vector<std::byte> &pkt, std::string_view name, uint16_t type, uint32_t ttl,
                               uint16_t rdlength)
{
    append(pkt, encode_name(name));
    push_u16_be(pkt, type);
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, ttl);
    push_u16_be(pkt, rdlength);
}

inline void push_a_record(std::vector<std::byte> &pkt, std::string_view name, uint8_t a, uint8_t b, uint8_t c,
                          uint8_t d)
{
    push_record_header(pkt, name, 1, 120, 4);
    append(pkt, bytes({a, b, c, d}));
}

inline void push_srv_record(std::vector<std::byte> &pkt, std::string_view name, std::string_view target,
                            uint16_t port)
{
    auto target_enc = encode_name(target);
    push_record_header(pkt, name, 33, 4500, static_cast<uint16_t>(6 + target_enc.size()));
    push_u16_be(pkt, 0);
    push_u16_be(pkt, 0);
    push_u16_be(pkt, port);
    append(pkt, target_enc);
}

inline std::vector<std::byte> make_a_response(std::string_view name, uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    std::vector<std::byte> pkt;
    push_header(pkt, 0x8400, 0, 1);
    push_a_record(pkt, name, a, b, c, d);
    return pkt;
}

inline std::vector<std::byte> make_srv_response(std::string_view name, std::string_view target, uint16_t port)
{
    std::vector<std::byte> pkt;
    push_header(pkt, 0x8400, 0, 1);
    push_srv_record(pkt, name, target, port);
    return pkt;
}

inline std::vector<std::byte> make_aaaa_response(std::string_view name, std::array<uint8_t, 16> addr)
{
    std::vector<std::byte> pkt;
    push_header(pkt, 0x8400, 0, 1);
    push_record_header(pkt, name, 28, 120, 16);
    for(uint8_t b : addr)
        pkt.push_back(static_cast<std::byte>(b));
    return pkt;
}

inline std::vector<std::byte> make_multi_record_response()
{
    std::vector<std::byte> pkt;
    push_header(pkt, 0x8400, 0, 2);
    push_a_record(pkt, "myhost.local.", 192, 168, 1, 1);
    push_srv_record(pkt, "myservice._tcp.local.", "myhost.local.", 8080);
    return pkt;
}

// The second A record declares RDLENGTH 5; an A record carries exactly four bytes.
inline std::vector<std::byte> make_malformed_a_response()
{
    std::vector<std::byte> pkt;
    push_header(pkt, 0x8400, 0, 2);
    push_a_record(pkt, "good.local.", 1, 2, 3, 4);
    push_record_header(pkt, "bad.local.", 1, 120, 5);
    append(pkt, bytes({5, 6, 7, 8, 0}));
    return pkt;
}

inline void push_question(std::vector<std::byte> &pkt, std::string_view name, uint16_t qtype, bool qu_bit)
{
    append(pkt, encode_name(name));
    push_u16_be(pkt, qtype);
    push_u16_be(pkt, qu_bit ? uint16_t{0x8001} : uint16_t{0x0001});
}

inline std::vector<std::byte> make_dns_query_packet(std::string_view name, uint16_t qtype, bool qu_bit = false)
{
    std::vector<std::byte> pkt;
    push_header(pkt, 0x0000, 1, 0);
    push_question(pkt, name, qtype, qu_bit);
    return pkt;
}

inline std::vector<std::byte> make_known_answer_query(std::string_view name)
{
    std::vector<std::byte> pkt;
    push_header(pkt, 0x0000, 1, 1);
    push_question(pkt, name, 1, false);
    push_a_record(pkt, name, 192, 168, 1, 1);
    return pkt;
}

#endif
