#ifndef HPP_GUARD_MDNSPP_DETAIL_DNS_READ_H
#define HPP_GUARD_MDNSPP_DETAIL_DNS_READ_H

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/byte_order.h"

#include "mdnspp/dns_name.h"
#include "mdnspp/mdns_error.h"

#include <span>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>

namespace mdnspp::detail {

// A compression pointer ends the walk unfollowed. Reserved label tags 01/10 (RFC 1035 §4.1.4) are rejected as
// read_dns_name rejects them (label_len > 63), so skip and read never disagree on record boundaries.
inline bool skip_dns_name(std::span<const std::byte> buf, size_t &offset)
{
    while(offset < buf.size())
    {
        uint8_t label_len = static_cast<uint8_t>(buf[offset]);

        if((label_len & 0xC0) == 0xC0)
        {
            if(offset + 1 >= buf.size())
                return false;
            offset += 2;
            return true;
        }

        if((label_len & 0xC0) != 0)
            return false;

        offset += 1 + static_cast<size_t>(label_len);
        if(label_len == 0)
            return true;
        if(offset > buf.size())
            return false;
    }
    return false;
}

// RFC 9267: the target must be strictly backward, which rules out self-reference and cycles by construction, and
// at most 4 pointer hops are allowed per name.
inline bool follow_compression_pointer(std::span<const std::byte> buf, size_t &offset, int &hops)
{
    constexpr int max_hops = 4;

    if(offset + 1 >= buf.size())
        return false;

    size_t ptr_target =
        ((static_cast<size_t>(static_cast<uint8_t>(buf[offset])) & 0x3FU) << 8) |
        static_cast<size_t>(static_cast<uint8_t>(buf[offset + 1]));

    if(ptr_target >= offset)
        return false;

    if(++hops > max_hops)
        return false;

    offset = ptr_target;
    return true;
}

// The 255-octet limit (RFC 1035 §3.1) is measured on the wire form, not the longer escaped presentation form.
inline bool append_wire_label(std::span<const std::byte> buf, size_t &offset, uint8_t label_len,
                              size_t &wire_len, std::string &result)
{
    constexpr size_t max_wire_len = 255;

    // RFC 1035 §2.3.4: labels are 6 bits, max 63 octets
    if(label_len > 63)
        return false;

    size_t label_start = offset + 1;
    size_t label_end = label_start + static_cast<size_t>(label_len);

    if(label_end > buf.size())
        return false;

    wire_len += 1 + static_cast<size_t>(label_len);
    if(wire_len > max_wire_len)
        return false;

    for(size_t i = label_start; i < label_end; ++i)
        append_escaped_label_byte(result, static_cast<char>(static_cast<uint8_t>(buf[i])));
    result += '.';

    offset = label_end;
    return true;
}

// RFC 1035 §4.1.4 decompression under the RFC 9267 pointer rules. Label bytes keep their case (RFC 6762 §16:
// comparison, not transmission, is case-insensitive); encode_dns_name turns the result back into identical wire bytes.
inline detail::expected<std::string, mdns_error>
read_dns_name(std::span<const std::byte> buf, size_t offset)
{
    std::string result;
    result.reserve(64);

    int hops = 0;
    size_t wire_len = 1; // root terminator

    while(offset < buf.size())
    {
        uint8_t label_len = static_cast<uint8_t>(buf[offset]);

        if((label_len & 0xC0) == 0xC0)
        {
            if(!follow_compression_pointer(buf, offset, hops))
                break;
        }
        else if(label_len == 0)
            return result;
        else if(!append_wire_label(buf, offset, label_len, wire_len, result))
            break;
    }
    return detail::unexpected(mdns_error::parse_error);
}

// Byte case is preserved. An invalid name fails as a whole: callers surface the failure, never emit a partial name.
inline detail::expected<std::vector<std::byte>, mdns_error>
encode_dns_name(std::string_view name)
{
    auto labels = parse_presentation_labels(name);
    if(!labels.has_value())
        return detail::unexpected(labels.error());

    size_t total = 1;
    for(const auto &label : *labels)
        total += 1 + label.size();

    std::vector<std::byte> result;
    result.reserve(total);

    for(const auto &label : *labels)
    {
        result.push_back(static_cast<std::byte>(static_cast<uint8_t>(label.size())));
        for(char c : label)
            result.push_back(static_cast<std::byte>(static_cast<uint8_t>(c)));
    }

    result.push_back(std::byte{0}); // root label
    return result;
}

}

#endif
