#ifndef HPP_GUARD_MDNSPP_PARSE_HELPERS_H
#define HPP_GUARD_MDNSPP_PARSE_HELPERS_H

#include "mdnspp/parse.h"
#include "mdnspp/records.h"

#include "mdnspp/detail/dns_frame.h"

#include "support/wire_bytes.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>

using namespace mdnspp;
using mdnspp::dns_type;
using mdnspp::dns_class;
using mdnspp::test_support::bytes;

inline record_metadata record_meta(dns_type rtype, std::size_t record_offset, std::size_t record_length)
{
    record_metadata meta;
    meta.rtype = rtype;
    meta.record_offset = record_offset;
    meta.record_length = record_length;
    return meta;
}

inline std::vector<std::byte> host_a_record(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    return bytes({0x04, 'h', 'o', 's', 't', 0x00, a, b, c, d});
}

inline std::vector<std::byte> ipv6_loopback()
{
    return bytes({0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x00,
                  0x00, 0x00, 0x00, 0x01});
}

#endif
