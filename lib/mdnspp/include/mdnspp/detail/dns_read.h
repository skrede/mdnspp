#ifndef HPP_GUARD_MDNSPP_DETAIL_DNS_READ_H
#define HPP_GUARD_MDNSPP_DETAIL_DNS_READ_H

#include "mdnspp/dns_name.h"
#include "mdnspp/mdns_error.h"

#include "mdnspp/detail/compat.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace mdnspp::detail {

// Reads a big-endian uint16 from two consecutive bytes.
// Uses shift-and-or — no reinterpret_cast, well-defined for std::byte.
inline uint16_t read_u16_be(const std::byte *p)
{
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(static_cast<uint8_t>(p[0])) << 8) |
        static_cast<uint16_t>(static_cast<uint8_t>(p[1]))
    );
}

// Reads a big-endian uint32 from four consecutive bytes.
inline uint32_t read_u32_be(const std::byte *p)
{
    return (static_cast<uint32_t>(static_cast<uint8_t>(p[0])) << 24) |
        (static_cast<uint32_t>(static_cast<uint8_t>(p[1])) << 16) |
        (static_cast<uint32_t>(static_cast<uint8_t>(p[2])) << 8) |
        static_cast<uint32_t>(static_cast<uint8_t>(p[3]));
}

// Appends a 16-bit value to buf in big-endian byte order (most-significant byte first).
inline void push_u16_be(std::vector<std::byte> &buf, uint16_t v)
{
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>(v >> 8)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>(v & 0xFF)));
}

// Appends a 32-bit value to buf in big-endian byte order.
inline void push_u32_be(std::vector<std::byte> &buf, uint32_t v)
{
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>((v >> 24) & 0xFF)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>((v >> 16) & 0xFF)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>((v >> 8) & 0xFF)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>(v & 0xFF)));
}

// Walks a DNS name at buf[offset], advancing offset past the name.
// Handles compression pointers (top 2 bits = 0xC0).
// Returns false if any read would go out of bounds.
inline bool skip_dns_name(std::span<const std::byte> buf, size_t &offset)
{
    while(true)
    {
        if(offset >= buf.size())
            return false;

        uint8_t label_len = static_cast<uint8_t>(buf[offset]);

        // Compression pointer: top 2 bits set to 11 (0xC0)
        if((label_len & 0xC0) == 0xC0)
        {
            // Pointer occupies 2 bytes; advance past them (don't follow)
            if(offset + 1 >= buf.size())
                return false;
            offset += 2;
            return true; // pointer ends name traversal
        }

        // Reserved label tags 01/10 (RFC 1035 §4.1.4): rejected exactly like
        // read_dns_name (label_len > 63), so skip and read can never disagree
        // on record boundaries.
        if((label_len & 0xC0) != 0)
            return false;

        if(label_len == 0)
        {
            // Root label — end of name
            offset += 1;
            return true;
        }

        // Regular label: skip length byte + label bytes
        offset += 1 + static_cast<size_t>(label_len);
        if(offset > buf.size())
            return false;
    }
}

// Reads and decompresses a DNS name from the wire format at the given offset.
//
// Implements RFC 1035 §4.1.4 name decompression with RFC 9267 safety rules:
//   - Backward-only compression pointers: ptr_target must be strictly less than
//     the current offset; self-referential and forward pointers are rejected.
//   - Maximum 4 pointer hops per name: prevents long chains even in the absence
//     of cycles (which are impossible by the backward-only invariant).
//   - Wire-encoded name must not exceed 255 bytes (RFC 1035 §3.1), measured
//     on the unescaped label bytes.
//   - Label bytes are transcribed with original case preserved (RFC 6762 §16:
//     comparison, not transmission, is case-insensitive) and RFC 1035 §5.1
//     escaping applied: '.' and '\' inside a label become "\." and "\\",
//     non-printable bytes become "\DDD"; bytes >= 0x80 stay verbatim (UTF-8).
//
// The result string uses escaped dotted-label FQDN notation with a trailing
// dot (e.g. "_http._tcp.local."). The root name (\x00) returns an empty
// string. encode_dns_name parses this form back to identical wire bytes.
//
// Returns detail::make_unexpected(mdns_error::parse_error) on any bounds violation,
// pointer safety violation, or name-length overflow.
inline detail::expected<std::string, mdns_error>
read_dns_name(std::span<const std::byte> buf, size_t offset)
{
    std::string result;
    result.reserve(64);

    int hops = 0;
    constexpr int max_hops = 4;
    constexpr size_t max_wire_len = 255;
    size_t wire_len = 1; // root terminator

    while(true)
    {
        if(offset >= buf.size())
            return detail::make_unexpected(mdns_error::parse_error);

        uint8_t label_len = static_cast<uint8_t>(buf[offset]);

        // Compression pointer: top 2 bits set (0xC0)
        if((label_len & 0xC0) == 0xC0)
        {
            // Pointer requires 2 bytes
            if(offset + 1 >= buf.size())
                return detail::make_unexpected(mdns_error::parse_error);

            size_t ptr_target =
                ((static_cast<size_t>(label_len) & 0x3FU) << 8) |
                static_cast<size_t>(static_cast<uint8_t>(buf[offset + 1]));

            // RFC 9267: pointer must be strictly backward — prevents self-referential
            // and forward pointers; cycles are impossible by construction.
            if(ptr_target >= offset)
                return detail::make_unexpected(mdns_error::parse_error);

            if(++hops > max_hops)
                return detail::make_unexpected(mdns_error::parse_error);

            offset = ptr_target;
            continue;
        }

        // Root label — name is complete (each label already appended its dot)
        if(label_len == 0)
            return result;

        // RFC 1035 §2.3.4: labels are 6 bits, max 63 octets
        if(label_len > 63)
            return detail::make_unexpected(mdns_error::parse_error);

        // Regular label: bounds-check, then append
        size_t label_start = offset + 1;
        size_t label_end = label_start + static_cast<size_t>(label_len);

        if(label_end > buf.size())
            return detail::make_unexpected(mdns_error::parse_error);

        // RFC 1035 §3.1: the limit applies to the wire form, not the
        // (potentially longer) escaped presentation form.
        wire_len += 1 + static_cast<size_t>(label_len);
        if(wire_len > max_wire_len)
            return detail::make_unexpected(mdns_error::parse_error);

        for(size_t i = label_start; i < label_end; ++i)
            append_escaped_label_byte(result, static_cast<char>(static_cast<uint8_t>(buf[i])));
        result += '.';

        offset = label_end;
    }
}

// Converts a presentation-format DNS name (RFC 1035 §5.1 escaping, e.g.
// "Dr\. Smith._http._tcp.local.") to wire label format with original byte
// case preserved. Escapes ("\.", "\\", "\DDD") are parsed; each unescaped
// label is prefixed by its length byte and the name is terminated by the
// \x00 root label. "" and "." encode the root name.
//
// Returns detail::make_unexpected(mdns_error::invalid_name) on empty labels
// ("a..b"), malformed escapes, labels over 63 octets or names over 255 wire
// octets — callers must surface the failure rather than emit a partial name.
inline detail::expected<std::vector<std::byte>, mdns_error>
encode_dns_name(std::string_view name)
{
    auto labels = parse_presentation_labels(name);
    if(!labels.has_value())
        return detail::make_unexpected(labels.error());

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
