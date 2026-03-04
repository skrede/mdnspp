#ifndef HPP_GUARD_MDNSPP_DNS_WIRE_H
#define HPP_GUARD_MDNSPP_DNS_WIRE_H

#include "mdnspp/parse.h"
#include "mdnspp/endpoint.h"

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <string_view>

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
           (static_cast<uint32_t>(static_cast<uint8_t>(p[2])) <<  8) |
            static_cast<uint32_t>(static_cast<uint8_t>(p[3]));
}

// Walks a DNS name at buf[offset], advancing offset past the name.
// Handles compression pointers (top 2 bits = 0xC0).
// Returns false if any read would go out of bounds.
inline bool skip_dns_name(std::span<const std::byte> buf, size_t &offset)
{
    while (true)
    {
        if (offset >= buf.size())
            return false;

        uint8_t label_len = static_cast<uint8_t>(buf[offset]);

        // Compression pointer: top 2 bits set to 11 (0xC0)
        if ((label_len & 0xC0) == 0xC0)
        {
            // Pointer occupies 2 bytes; advance past them (don't follow)
            if (offset + 1 >= buf.size())
                return false;
            offset += 2;
            return true; // pointer ends name traversal
        }

        if (label_len == 0)
        {
            // Root label — end of name
            offset += 1;
            return true;
        }

        // Regular label: skip length byte + label bytes
        offset += 1 + static_cast<size_t>(label_len);
        if (offset > buf.size())
            return false;
    }
}

// Converts a DNS name string (e.g. "_http._tcp.local.") to wire label format.
// Strips trailing dot if present. Each label is prefixed by its length byte.
// Terminates with \x00 root label.
inline std::vector<std::byte> encode_dns_name(std::string_view name)
{
    std::vector<std::byte> result;

    // Strip trailing dot
    if (!name.empty() && name.back() == '.')
        name.remove_suffix(1);

    size_t pos = 0;
    while (pos < name.size())
    {
        size_t dot = name.find('.', pos);
        if (dot == std::string_view::npos)
            dot = name.size();

        size_t label_len = dot - pos;
        result.push_back(static_cast<std::byte>(static_cast<uint8_t>(label_len)));
        for (size_t i = pos; i < dot; ++i)
            result.push_back(static_cast<std::byte>(static_cast<uint8_t>(name[i])));

        pos = (dot < name.size()) ? dot + 1 : name.size();
    }

    // Root label
    result.push_back(static_cast<std::byte>(0x00));
    return result;
}

// Builds a complete mDNS query packet:
//   12-byte header (id=0, flags=0, questions=1, answers=0, authority=0, additional=0)
//   + DNS-encoded name
//   + qtype (big-endian, 2 bytes)
//   + qclass = 0x0001 (IN / multicast, 2 bytes)
inline std::vector<std::byte> build_dns_query(std::string_view name, uint16_t qtype)
{
    std::vector<std::byte> packet;
    packet.reserve(12 + 256 + 4);

    // 12-byte DNS header
    // Transaction ID: 0x0000
    packet.push_back(static_cast<std::byte>(0x00));
    packet.push_back(static_cast<std::byte>(0x00));
    // Flags: 0x0000 (standard query)
    packet.push_back(static_cast<std::byte>(0x00));
    packet.push_back(static_cast<std::byte>(0x00));
    // Questions: 1
    packet.push_back(static_cast<std::byte>(0x00));
    packet.push_back(static_cast<std::byte>(0x01));
    // Answers: 0
    packet.push_back(static_cast<std::byte>(0x00));
    packet.push_back(static_cast<std::byte>(0x00));
    // Authority: 0
    packet.push_back(static_cast<std::byte>(0x00));
    packet.push_back(static_cast<std::byte>(0x00));
    // Additional: 0
    packet.push_back(static_cast<std::byte>(0x00));
    packet.push_back(static_cast<std::byte>(0x00));

    // Encoded question name
    auto encoded = encode_dns_name(name);
    packet.insert(packet.end(), encoded.begin(), encoded.end());

    // QTYPE (big-endian)
    packet.push_back(static_cast<std::byte>(static_cast<uint8_t>(qtype >> 8)));
    packet.push_back(static_cast<std::byte>(static_cast<uint8_t>(qtype & 0xFF)));

    // QCLASS = 0x0001 (IN)
    packet.push_back(static_cast<std::byte>(0x00));
    packet.push_back(static_cast<std::byte>(0x01));

    return packet;
}

// Walks a DNS response frame, calling on_record(mdns_record_variant) for each
// successfully parsed resource record. Silently skips malformed records.
//
// Template parameter Callback: callable accepting mdns_record_variant by value.
template <typename Callback>
void walk_dns_frame(std::span<const std::byte> data, endpoint sender, Callback &&on_record)
{
    // Need at least 12 bytes for DNS header
    if (data.size() < 12)
        return;

    const std::byte *buf = data.data();

    // Parse header counts
    uint16_t qdcount = read_u16_be(buf + 4);  // questions
    uint16_t ancount = read_u16_be(buf + 6);  // answers
    uint16_t nscount = read_u16_be(buf + 8);  // authority
    uint16_t arcount = read_u16_be(buf + 10); // additional

    size_t offset = 12;

    // Skip questions section (name + qtype(2) + qclass(2))
    for (uint16_t i = 0; i < qdcount; ++i)
    {
        if (!skip_dns_name(data, offset))
            return;
        offset += 4; // qtype + qclass
        if (offset > data.size())
            return;
    }

    // Parse RRs: answer + authority + additional
    uint32_t rr_total = static_cast<uint32_t>(ancount) +
                        static_cast<uint32_t>(nscount) +
                        static_cast<uint32_t>(arcount);

    for (uint32_t rr = 0; rr < rr_total; ++rr)
    {
        // Record name offset (for record_metadata.name_offset)
        size_t name_offset = offset;

        if (!skip_dns_name(data, offset))
            return;

        // Need rtype(2) + rclass(2) + ttl(4) + rdlength(2) = 10 bytes
        if (offset + 10 > data.size())
            return;

        uint16_t rtype    = read_u16_be(buf + offset);       offset += 2;
        uint16_t rclass   = read_u16_be(buf + offset);       offset += 2;
        uint32_t ttl      = read_u32_be(buf + offset);       offset += 4;
        uint16_t rdlength = read_u16_be(buf + offset);       offset += 2;

        size_t record_offset = offset;
        size_t record_length = static_cast<size_t>(rdlength);

        // Bounds check for rdata
        if (record_offset + record_length > data.size())
            return;

        record_metadata meta;
        meta.sender        = sender;
        meta.ttl           = ttl;
        meta.rclass        = rclass & 0x7FFF; // strip cache-flush bit
        meta.rtype         = rtype;
        meta.name_offset   = name_offset;
        meta.record_offset = record_offset;
        meta.record_length = record_length;

        // Attempt to parse the record; silently skip on failure
        auto result = parse::record(data, meta);
        if (result.has_value())
            on_record(std::move(*result));

        // Advance past rdata regardless of parse success
        offset = record_offset + record_length;
    }
}

} // namespace mdnspp::detail

#endif // HPP_GUARD_MDNSPP_DNS_WIRE_H
