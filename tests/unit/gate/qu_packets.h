#ifndef HPP_GUARD_MDNSPP_GATE_QU_PACKETS_H
#define HPP_GUARD_MDNSPP_GATE_QU_PACKETS_H

#include "support/wire_bytes.h"

#include <vector>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <initializer_list>

inline constexpr uint16_t ptr_type = 12;
inline constexpr uint16_t any_value = 255;
inline constexpr uint16_t in_class = 1;
inline constexpr uint16_t qu_in_class = 0x8001;

struct wire_entry
{
    std::string_view name;
    uint16_t type;
    uint16_t rclass;
    std::string_view target;
};

inline void push_entries(std::vector<std::byte> &packet, std::initializer_list<wire_entry> entries, bool with_rdata)
{
    using mdnspp::test_support::encode_name;
    using mdnspp::test_support::push_u16_be;
    for(const wire_entry &entry : entries)
    {
        const std::vector<std::byte> name = encode_name(entry.name);
        packet.insert(packet.end(), name.begin(), name.end());
        push_u16_be(packet, entry.type);
        push_u16_be(packet, entry.rclass);
        if(!with_rdata)
            continue;
        const std::vector<std::byte> rdata = encode_name(entry.target);
        mdnspp::test_support::push_u32_be(packet, 120);
        push_u16_be(packet, static_cast<uint16_t>(rdata.size()));
        packet.insert(packet.end(), rdata.begin(), rdata.end());
    }
}

inline std::vector<std::byte> dns_header(uint16_t flags, std::size_t qd, std::size_t an, std::size_t ar)
{
    std::vector<std::byte> packet;
    for(const std::size_t value : {std::size_t{0}, std::size_t{flags}, qd, an, std::size_t{0}, ar})
        mdnspp::test_support::push_u16_be(packet, static_cast<uint16_t>(value));
    return packet;
}

inline std::vector<std::byte> question_packet(std::initializer_list<wire_entry> questions)
{
    std::vector<std::byte> packet = dns_header(0x0000, questions.size(), 0, 0);
    push_entries(packet, questions, false);
    return packet;
}

inline std::vector<std::byte> answer_packet(std::initializer_list<wire_entry> answers,
                                            std::initializer_list<wire_entry> additional = {})
{
    std::vector<std::byte> packet = dns_header(0x8400, 0, answers.size(), additional.size());
    push_entries(packet, answers, true);
    push_entries(packet, additional, true);
    return packet;
}

#endif
