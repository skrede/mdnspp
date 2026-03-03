#ifndef HPP_GUARD_MDNSPP_PARSE_H
#define HPP_GUARD_MDNSPP_PARSE_H

#include "mdnspp/records.h"
#include "mdnspp/mdns_error.h"
#include "mdnspp/endpoint.h"

#include <span>
#include <expected>
#include <cstdint>
#include <cstddef>

namespace mdnspp {

struct record_metadata
{
    endpoint sender;
    uint32_t ttl{0};
    uint16_t rclass{0};
    uint16_t rtype{0};       // 1=A, 12=PTR, 16=TXT, 28=AAAA, 33=SRV
    size_t   name_offset{0};
    size_t   record_offset{0};
    size_t   record_length{0};
};

namespace parse {

std::expected<mdns_record_variant, mdns_error>
ptr(std::span<const std::byte> buffer, const record_metadata &meta);

std::expected<mdns_record_variant, mdns_error>
srv(std::span<const std::byte> buffer, const record_metadata &meta);

std::expected<mdns_record_variant, mdns_error>
a(std::span<const std::byte> buffer, const record_metadata &meta);

std::expected<mdns_record_variant, mdns_error>
aaaa(std::span<const std::byte> buffer, const record_metadata &meta);

std::expected<mdns_record_variant, mdns_error>
txt(std::span<const std::byte> buffer, const record_metadata &meta);

std::expected<mdns_record_variant, mdns_error>
record(std::span<const std::byte> buffer, const record_metadata &meta);

} // namespace parse

} // namespace mdnspp

#endif // HPP_GUARD_MDNSPP_PARSE_H
