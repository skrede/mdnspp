#ifndef HPP_GUARD_MDNSPP_DISCOVERY_HELPERS_H
#define HPP_GUARD_MDNSPP_DISCOVERY_HELPERS_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/resolved_service.h"
#include "mdnspp/basic_service_discovery.h"

#include "mdnspp/testing/mock_policy.h"

#include <chrono>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <string_view>

using namespace mdnspp;
using namespace mdnspp::testing;
using namespace std::chrono_literals;

inline std::vector<std::byte> bytes(std::initializer_list<unsigned char> vals)
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

inline std::vector<std::byte> make_ptr_response(std::string_view owner,
                                                std::string_view target)
{
    std::vector<std::byte> pkt;

    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x8400);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0001);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0000);

    auto owner_enc = encode_name(owner);
    auto target_enc = encode_name(target);

    pkt.insert(pkt.end(), owner_enc.begin(), owner_enc.end());
    push_u16_be(pkt, 12);
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, 4500);
    push_u16_be(pkt, static_cast<uint16_t>(target_enc.size()));
    pkt.insert(pkt.end(), target_enc.begin(), target_enc.end());

    return pkt;
}

inline std::vector<std::byte> make_a_response(std::string_view owner,
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

    auto owner_enc = encode_name(owner);
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

inline std::vector<std::byte> make_multi_record_response()
{
    std::vector<std::byte> pkt;

    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x8400);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0002);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0000);

    auto owner_enc = encode_name("_http._tcp.local.");
    auto target_enc = encode_name("MyService._http._tcp.local.");

    pkt.insert(pkt.end(), owner_enc.begin(), owner_enc.end());
    push_u16_be(pkt, 12);
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, 4500);
    push_u16_be(pkt, static_cast<uint16_t>(target_enc.size()));
    pkt.insert(pkt.end(), target_enc.begin(), target_enc.end());

    auto host_enc = encode_name("myhost.local.");
    pkt.insert(pkt.end(), host_enc.begin(), host_enc.end());
    push_u16_be(pkt, 1);
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, 120);
    push_u16_be(pkt, 4);
    pkt.push_back(static_cast<std::byte>(192));
    pkt.push_back(static_cast<std::byte>(168));
    pkt.push_back(static_cast<std::byte>(0));
    pkt.push_back(static_cast<std::byte>(1));

    return pkt;
}

inline std::vector<std::byte> make_srv_response(std::string_view owner,
                                                std::string_view target_hostname,
                                                uint16_t port)
{
    std::vector<std::byte> pkt;

    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x8400);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0001);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0000);

    auto owner_enc = encode_name(owner);
    auto target_enc = encode_name(target_hostname);

    pkt.insert(pkt.end(), owner_enc.begin(), owner_enc.end());
    push_u16_be(pkt, 33);
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, 120);

    auto rdlength = static_cast<uint16_t>(2 + 2 + 2 + target_enc.size());
    push_u16_be(pkt, rdlength);
    push_u16_be(pkt, 0);
    push_u16_be(pkt, 0);
    push_u16_be(pkt, port);
    pkt.insert(pkt.end(), target_enc.begin(), target_enc.end());

    return pkt;
}

inline std::vector<std::byte> make_full_service_response(
    std::string_view instance_name,
    std::string_view service_type,
    std::string_view hostname,
    uint16_t port,
    uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    std::vector<std::byte> pkt;

    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x8400);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0003);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0000);

    auto svc_enc = encode_name(service_type);
    auto instance_enc = encode_name(instance_name);
    pkt.insert(pkt.end(), svc_enc.begin(), svc_enc.end());
    push_u16_be(pkt, 12);
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, 4500);
    push_u16_be(pkt, static_cast<uint16_t>(instance_enc.size()));
    pkt.insert(pkt.end(), instance_enc.begin(), instance_enc.end());

    auto host_enc = encode_name(hostname);
    pkt.insert(pkt.end(), instance_enc.begin(), instance_enc.end());
    push_u16_be(pkt, 33);
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, 120);
    push_u16_be(pkt, static_cast<uint16_t>(2 + 2 + 2 + host_enc.size()));
    push_u16_be(pkt, 0);
    push_u16_be(pkt, 0);
    push_u16_be(pkt, port);
    pkt.insert(pkt.end(), host_enc.begin(), host_enc.end());

    pkt.insert(pkt.end(), host_enc.begin(), host_enc.end());
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

#endif
