#ifndef HPP_GUARD_MDNSPP_DNS_READ_H
#define HPP_GUARD_MDNSPP_DNS_READ_H

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
//   - Assembled name must not exceed 255 bytes (RFC 1035 §3.1).
//   - Labels are transcribed as raw bytes (no IDN/punycode — mDNS names are ASCII).
//
// The result string uses dotted-label FQDN notation with a trailing dot
// (e.g. "_http._tcp.local."). The root name (\x00) returns an empty string.
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
    constexpr size_t max_name_len = 255;

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

        // Root label — name is complete; append trailing dot for FQDN form
        if(label_len == 0)
        {
            if(!result.empty())
                result += '.';
            return result;
        }

        // Regular label: bounds-check, then append
        size_t label_start = offset + 1;
        size_t label_end = label_start + static_cast<size_t>(label_len);

        if(label_end > buf.size())
            return detail::make_unexpected(mdns_error::parse_error);

        if(!result.empty())
            result += '.';

        for(size_t i = label_start; i < label_end; ++i)
            result += static_cast<char>(static_cast<uint8_t>(buf[i]));

        // +1 accounts for the trailing dot appended at name completion
        if(result.size() + 1 > max_name_len)
            return detail::make_unexpected(mdns_error::parse_error);

        offset = label_end;
    }
}

// Converts a DNS name string (e.g. "_http._tcp.local.") to wire label format.
// Strips trailing dot if present. Each label is prefixed by its length byte.
// Terminates with \x00 root label.
inline std::vector<std::byte> encode_dns_name(std::string_view name)
{
    std::vector<std::byte> result;
    if(name.empty())
    {
        result.push_back(std::byte{0});
        return result;
    }

    // Strip trailing dot if present
    if(name.back() == '.')
        name.remove_suffix(1);

    size_t pos = 0;
    while(pos < name.size())
    {
        size_t dot = name.find('.', pos);
        if(dot == std::string_view::npos)
            dot = name.size();

        size_t label_len = dot - pos;
        result.push_back(static_cast<std::byte>(static_cast<uint8_t>(label_len)));
        for(size_t i = pos; i < dot; ++i)
            result.push_back(static_cast<std::byte>(static_cast<uint8_t>(name[i])));

        pos = dot + 1;
    }

    result.push_back(std::byte{0}); // root label
    return result;
}

}

#endif
