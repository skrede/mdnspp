#ifndef HPP_GUARD_MDNSPP_SERVER_QUERY_HELPERS_H
#define HPP_GUARD_MDNSPP_SERVER_QUERY_HELPERS_H

#include "helpers.h"

#include <cstdint>
#include <algorithm>
#include <string_view>
#include <initializer_list>

struct question_entry
{
    std::string_view name;
    dns_type qtype;
    bool qu_bit;
};

inline std::vector<std::byte> make_multi_question_query(std::initializer_list<question_entry> questions)
{
    std::vector<std::byte> packet;
    packet.reserve(12 + 256 * questions.size());
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, static_cast<uint16_t>(questions.size()));
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, 0x0000);
    for(const auto &q : questions)
    {
        auto encoded = encode_dns_name(q.name).value();
        packet.insert(packet.end(), encoded.begin(), encoded.end());
        push_u16_be(packet, mdnspp::detail::to_underlying(q.qtype));
        push_u16_be(packet, q.qu_bit ? uint16_t{0x8001} : uint16_t{0x0001});
    }
    return packet;
}

inline std::vector<std::byte> make_question_packet(uint16_t flags, std::string_view name, dns_type qtype,
                                                   uint16_t qclass)
{
    std::vector<std::byte> packet;
    for(uint16_t field : {uint16_t{0x0000}, flags, uint16_t{1}, uint16_t{0}, uint16_t{0}, uint16_t{0}})
        push_u16_be(packet, field);
    auto encoded = encode_dns_name(name).value();
    packet.insert(packet.end(), encoded.begin(), encoded.end());
    push_u16_be(packet, mdnspp::detail::to_underlying(qtype));
    push_u16_be(packet, qclass);
    return packet;
}

// Probes carry flags 0x0000; announcements and responses carry 0x8400.
inline unsigned count_multicast_responses_after(const std::vector<sent_packet> &packets, size_t start_index)
{
    unsigned count = 0;
    for(size_t i = start_index; i < packets.size(); ++i)
    {
        if(packets[i].dest == endpoint{"224.0.0.251", 5353} && packets[i].data.size() >= 12)
            count += read_u16_be(packets[i].data, 2) == 0x8400 ? 1u : 0u;
    }
    return count;
}

inline std::vector<std::byte> make_tc_ptr_query(std::string_view service_type)
{
    auto pkt = build_dns_query(service_type, dns_type::ptr);
    pkt[2] = static_cast<std::byte>(static_cast<uint8_t>(pkt[2]) | 0x02u);
    return pkt;
}

inline bool sent_to(const std::vector<sent_packet> &packets, const endpoint &dest)
{
    return std::ranges::any_of(packets, [&](const sent_packet &p) { return p.dest == dest; });
}

inline const dns_name &owner_of(const record_ptr &record) { return record.ptr_name; }

inline const dns_name &owner_of(const record_srv &record) { return record.name; }

template<typename Record>
inline bool response_has(const std::vector<std::byte> &data, std::string_view fragment = {})
{
    for(const auto &rv : parse_response(data))
    {
        if(std::holds_alternative<Record>(rv) &&
           owner_of(std::get<Record>(rv)).str().find(fragment) != std::string::npos)
            return true;
    }
    return false;
}

inline bool any_response_has_ptr(const std::vector<sent_packet> &packets, std::string_view fragment)
{
    return std::ranges::any_of(packets, [&](const sent_packet &p)
    {
        return p.data.size() >= 12 && read_u16_be(p.data, 2) == 0x8400 &&
               response_has<record_ptr>(p.data, fragment);
    });
}

struct live_server
{
    mock_executor ex;
    basic_service_server<mock_policy> server;

    live_server()
        : ex{}, server{ex, make_test_service()}
    {
        server.async_start();
        advance_to_live(server);
        server.socket().clear_sent();
    }

    void inject(const endpoint &from, std::vector<std::byte> query)
    {
        server.socket().inject_receive(from, std::move(query));
    }

    void inject_query(const endpoint &from, std::string_view name, dns_type type, response_mode mode)
    {
        inject(from, build_dns_query(name, type, mode));
    }

    const std::vector<sent_packet> &sent() { return server.socket().sent_packets(); }

    const std::vector<std::byte> &last_data() { return sent().back().data; }
};

#endif
