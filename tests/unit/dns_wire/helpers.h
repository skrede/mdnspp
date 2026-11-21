#ifndef HPP_GUARD_MDNSPP_DNS_WIRE_HELPERS_H
#define HPP_GUARD_MDNSPP_DNS_WIRE_HELPERS_H

#include "packets.h"

#include "mdnspp/detail/dns_wire.h"

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_error.h"
#include "mdnspp/service_info.h"

#include "support/wire_bytes.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <string>
#include <vector>
#include <cstddef>
#include <variant>
#include <optional>

using mdnspp::test_support::bytes;
using mdnspp::test_support::read_u16_be;

static_assert(
    std::is_same_v<
        decltype(mdnspp::detail::read_dns_name(
            std::span<const std::byte>{},
            std::size_t{})),
        mdnspp::detail::expected<std::string, mdnspp::mdns_error>>,
    "read_dns_name must return detail::expected<std::string, mdns_error>");

#endif
