#ifndef HPP_GUARD_MDNSPP_QUERIER_HELPERS_H
#define HPP_GUARD_MDNSPP_QUERIER_HELPERS_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/basic_querier.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/testing/mock_policy.h"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <chrono>
#include <string>
#include <vector>
#include <cstddef>

using namespace mdnspp;
using namespace mdnspp::testing;
using namespace std::chrono_literals;

[[maybe_unused]] inline std::vector<std::byte> bytes(std::initializer_list<unsigned char> vals)
{
    std::vector<std::byte> v;
    v.reserve(vals.size());
    for(auto b : vals)
        v.push_back(static_cast<std::byte>(b));
    return v;
}

inline void push_u16_be(std::vector<std::byte> &buf, uint16_t v)
{
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>(v >> 8)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>(v & 0xFF)));
}

inline void push_u32_be(std::vector<std::byte> &buf, uint32_t v)
{
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>((v >> 24) & 0xFF)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>((v >> 16) & 0xFF)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>((v >> 8) & 0xFF)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>(v & 0xFF)));
}

inline std::vector<std::byte> encode_name(std::string_view name)
{
    std::vector<std::byte> result;
    if(!name.empty() && name.back() == '.')
        name.remove_suffix(1);

    size_t pos = 0;
    while(pos < name.size())
    {
        size_t dot = name.find('.', pos);
        if(dot == std::string_view::npos)
            dot = name.size();
        size_t len = dot - pos;
        result.push_back(static_cast<std::byte>(static_cast<uint8_t>(len)));
        for(size_t i = pos; i < dot; ++i)
            result.push_back(static_cast<std::byte>(static_cast<uint8_t>(name[i])));
        pos = (dot < name.size()) ? dot + 1 : name.size();
    }
    result.push_back(static_cast<std::byte>(0x00));
    return result;
}

inline std::vector<std::byte> make_a_response(std::string_view name,
                                              uint8_t a, uint8_t b,
                                              uint8_t c, uint8_t d)
{
    std::vector<std::byte> pkt;

    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x8400);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0001);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0000);

    auto owner_enc = encode_name(name);
    pkt.insert(pkt.end(), owner_enc.begin(), owner_enc.end());
    push_u16_be(pkt, 1);
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, 120);
    push_u16_be(pkt, 4);
    pkt.push_back(static_cast<std::byte>(a));
    pkt.push_back(static_cast<std::byte>(b));
    pkt.push_back(static_cast<std::byte>(c));
    pkt.push_back(static_cast<std::byte>(d));

    return pkt;
}

[[maybe_unused]] inline std::vector<std::byte> make_srv_response(std::string_view name,
                                                                 std::string_view target,
                                                                 uint16_t port)
{
    std::vector<std::byte> pkt;

    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x8400);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0001);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0000);

    auto owner_enc = encode_name(name);
    auto target_enc = encode_name(target);

    pkt.insert(pkt.end(), owner_enc.begin(), owner_enc.end());
    push_u16_be(pkt, 33);
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, 4500);

    uint16_t rdlength = static_cast<uint16_t>(6 + target_enc.size());
    push_u16_be(pkt, rdlength);
    push_u16_be(pkt, 0);
    push_u16_be(pkt, 0);
    push_u16_be(pkt, port);
    pkt.insert(pkt.end(), target_enc.begin(), target_enc.end());

    return pkt;
}

[[maybe_unused]] inline std::vector<std::byte> make_aaaa_response(std::string_view name,
                                                                  std::array<uint8_t, 16> addr)
{
    std::vector<std::byte> pkt;

    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x8400);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0001);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0000);

    auto owner_enc = encode_name(name);
    pkt.insert(pkt.end(), owner_enc.begin(), owner_enc.end());
    push_u16_be(pkt, 28);
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, 120);
    push_u16_be(pkt, 16);

    for(uint8_t b : addr)
        pkt.push_back(static_cast<std::byte>(b));

    return pkt;
}

inline std::vector<std::byte> make_multi_record_response()
{
    std::vector<std::byte> pkt;

    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x8400);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0002);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0000);

    auto a_enc = encode_name("myhost.local.");
    pkt.insert(pkt.end(), a_enc.begin(), a_enc.end());
    push_u16_be(pkt, 1);
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, 120);
    push_u16_be(pkt, 4);
    pkt.push_back(static_cast<std::byte>(192));
    pkt.push_back(static_cast<std::byte>(168));
    pkt.push_back(static_cast<std::byte>(1));
    pkt.push_back(static_cast<std::byte>(1));

    auto srv_name_enc = encode_name("myservice._tcp.local.");
    auto srv_target_enc = encode_name("myhost.local.");
    pkt.insert(pkt.end(), srv_name_enc.begin(), srv_name_enc.end());
    push_u16_be(pkt, 33);
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, 4500);
    push_u16_be(pkt, static_cast<uint16_t>(6 + srv_target_enc.size()));
    push_u16_be(pkt, 0);
    push_u16_be(pkt, 0);
    push_u16_be(pkt, 8080);
    pkt.insert(pkt.end(), srv_target_enc.begin(), srv_target_enc.end());

    return pkt;
}

inline std::vector<std::byte> make_dns_query_packet(std::string_view name, uint16_t qtype,
                                                    bool qu_bit = false)
{
    std::vector<std::byte> pkt;
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0001);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0000);

    auto enc = encode_name(name);
    pkt.insert(pkt.end(), enc.begin(), enc.end());
    push_u16_be(pkt, qtype);
    push_u16_be(pkt, qu_bit ? uint16_t{0x8001} : uint16_t{0x0001});

    return pkt;
}

#endif
