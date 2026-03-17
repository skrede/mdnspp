#ifndef HPP_GUARD_MDNSPP_HELPERS_H
#define HPP_GUARD_MDNSPP_HELPERS_H

#include "mdnspp/detail/dns_wire.h"

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_error.h"
#include "mdnspp/service_info.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <string>
#include <vector>
#include <cstddef>
#include <variant>
#include <optional>

namespace {

inline uint16_t read_u16_be(const auto &buf, std::size_t offset)
{
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(static_cast<uint8_t>(buf[offset])) << 8) |
        static_cast<uint16_t>(static_cast<uint8_t>(buf[offset + 1])));
}

}

static_assert(
    std::is_same_v<
        decltype(mdnspp::detail::read_dns_name(
            std::span<const std::byte>{},
            std::size_t{})),
        mdnspp::detail::expected<std::string, mdnspp::mdns_error>>,
    "read_dns_name must return detail::expected<std::string, mdns_error>");

inline std::vector<std::byte> bytes(std::initializer_list<unsigned char> vals)
{
    std::vector<std::byte> v;
    v.reserve(vals.size());
    for(auto b : vals)
        v.push_back(static_cast<std::byte>(b));
    return v;
}

#endif
