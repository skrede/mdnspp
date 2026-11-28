#ifndef HPP_GUARD_MDNSPP_DISCOVERY_PACKETS_H
#define HPP_GUARD_MDNSPP_DISCOVERY_PACKETS_H

#include "support/wire_bytes.h"

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

inline void push_response_header(std::vector<std::byte> &pkt, uint16_t ancount)
{
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x8400);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, ancount);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0000);
}

inline void push_record_header(std::vector<std::byte> &pkt, std::string_view owner, uint16_t type, uint32_t ttl,
                               uint16_t rdlength)
{
    append(pkt, encode_name(owner));
    push_u16_be(pkt, type);
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, ttl);
    push_u16_be(pkt, rdlength);
}

inline void push_ptr_record(std::vector<std::byte> &pkt, std::string_view owner, std::string_view target)
{
    auto target_enc = encode_name(target);
    push_record_header(pkt, owner, 12, 4500, static_cast<uint16_t>(target_enc.size()));
    append(pkt, target_enc);
}

inline void push_a_record(std::vector<std::byte> &pkt, std::string_view owner, uint8_t a, uint8_t b, uint8_t c,
                          uint8_t d)
{
    push_record_header(pkt, owner, 1, 120, 4);
    append(pkt, bytes({a, b, c, d}));
}

inline void push_srv_record(std::vector<std::byte> &pkt, std::string_view owner, std::string_view target,
                            uint16_t port)
{
    auto target_enc = encode_name(target);
    push_record_header(pkt, owner, 33, 120, static_cast<uint16_t>(2 + 2 + 2 + target_enc.size()));
    push_u16_be(pkt, 0);
    push_u16_be(pkt, 0);
    push_u16_be(pkt, port);
    append(pkt, target_enc);
}

inline std::vector<std::byte> make_ptr_response(std::string_view owner, std::string_view target)
{
    std::vector<std::byte> pkt;
    push_response_header(pkt, 1);
    push_ptr_record(pkt, owner, target);
    return pkt;
}

inline std::vector<std::byte> make_a_response(std::string_view owner, uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    std::vector<std::byte> pkt;
    push_response_header(pkt, 1);
    push_a_record(pkt, owner, a, b, c, d);
    return pkt;
}

inline std::vector<std::byte> make_multi_record_response()
{
    std::vector<std::byte> pkt;
    push_response_header(pkt, 2);
    push_ptr_record(pkt, "_http._tcp.local.", "MyService._http._tcp.local.");
    push_a_record(pkt, "myhost.local.", 192, 168, 0, 1);
    return pkt;
}

// The A record declares RDLENGTH 5; an A record carries exactly four bytes.
inline std::vector<std::byte> make_malformed_a_response()
{
    std::vector<std::byte> pkt;
    push_response_header(pkt, 2);
    push_ptr_record(pkt, "_http._tcp.local.", "Good._http._tcp.local.");
    push_record_header(pkt, "bad.local.", 1, 120, 5);
    append(pkt, bytes({192, 168, 0, 1, 0}));
    return pkt;
}

inline std::vector<std::byte> make_srv_response(std::string_view owner, std::string_view target_hostname,
                                                uint16_t port)
{
    std::vector<std::byte> pkt;
    push_response_header(pkt, 1);
    push_srv_record(pkt, owner, target_hostname, port);
    return pkt;
}

inline std::vector<std::byte> make_full_service_response(std::string_view instance_name, std::string_view service_type,
                                                         std::string_view hostname, uint16_t port, uint8_t a,
                                                         uint8_t b, uint8_t c, uint8_t d)
{
    std::vector<std::byte> pkt;
    push_response_header(pkt, 3);
    push_ptr_record(pkt, service_type, instance_name);
    push_srv_record(pkt, instance_name, hostname, port);
    push_a_record(pkt, hostname, a, b, c, d);
    return pkt;
}

#endif
