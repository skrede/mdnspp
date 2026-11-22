#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_QUESTION_SECTION_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_QUESTION_SECTION_H

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <optional>

namespace mdnspp::detail {

struct parsed_question
{
    std::size_t name_start;
    dns_type qtype;
    uint16_t qclass;
};

inline std::optional<parsed_question> read_question(std::span<const std::byte> data, std::size_t &offset)
{
    std::size_t name_start = offset;
    if(!skip_dns_name(data, offset))
        return std::nullopt;
    if(offset + 4 > data.size())
        return std::nullopt;
    const std::byte *buf = data.data();
    dns_type qtype = static_cast<dns_type>(read_u16_be(buf + offset));
    uint16_t qclass = read_u16_be(buf + offset + 2);
    offset += 4;
    return parsed_question{name_start, qtype, qclass};
}

// The QU bit (top bit of QCLASS) is meaningless in a response, so it is cleared.
inline bool append_uncompressed_question(std::vector<std::byte> &section, std::span<const std::byte> data,
                                         std::size_t &offset)
{
    auto decoded = read_dns_name(data, offset);
    if(!decoded.has_value() || !skip_dns_name(data, offset))
        return false;
    if(offset + 4 > data.size())
        return false;
    auto encoded = encode_dns_name(*decoded);
    if(!encoded.has_value())
        return false;
    uint16_t qtype = read_u16_be(data.data() + offset);
    uint16_t qclass = static_cast<uint16_t>(read_u16_be(data.data() + offset + 2) & 0x7FFFu);
    offset += 4;
    section.insert(section.end(), encoded->begin(), encoded->end());
    push_u16_be(section, qtype);
    push_u16_be(section, qclass);
    return true;
}

// Legacy unicast responses repeat the question section (RFC 6762 section 6.7), here without compression pointers.
// A question that cannot be rebuilt, or a packet shorter than a header, gives an empty section and 0.
inline std::pair<std::vector<std::byte>, uint16_t> rebuild_question_section(std::span<const std::byte> data)
{
    if(data.size() < 12)
        return {};
    uint16_t qdcount = read_u16_be(data.data() + 4);
    std::vector<std::byte> section;
    uint16_t rebuilt = 0;
    std::size_t offset = 12;
    for(uint16_t i = 0; i < qdcount; ++i)
    {
        if(!append_uncompressed_question(section, data, offset))
            return {};
        ++rebuilt;
    }
    return {std::move(section), rebuilt};
}

}

#endif
