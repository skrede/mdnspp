#include "interfaces.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_options.h"

#include "mdnspp/detail/packet_gate.h"
#include "mdnspp/detail/ip_address_ops.h"

#include "mdnspp/testing/mock_policy.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <cstddef>
#include <cstdint>
#include <optional>

using mdnspp::ttl_unknown_policy;

namespace {

using gate = mdnspp::detail::packet_gate<mdnspp::testing::mock_policy>;

std::vector<std::byte> header_only(uint16_t flags)
{
    std::vector<std::byte> packet(12, std::byte{0});
    packet[2] = static_cast<std::byte>(flags >> 8);
    packet[3] = static_cast<std::byte>(flags & 0xFFU);
    return packet;
}

const std::vector<std::byte> response = header_only(0x8400);
const std::vector<std::byte> query = header_only(0x0000);

mdnspp::recv_metadata with_ttl(std::optional<uint8_t> ttl)
{
    mdnspp::recv_metadata meta;
    meta.sender = mdnspp::endpoint{"192.0.2.10", 5353};
    meta.ttl = ttl;
    meta.destination = mdnspp::detail::parse_ip_address("224.0.0.251");
    return meta;
}

}

TEST_CASE("packet_gate with ttl_unknown_policy::accept admits a response of unknown TTL", "[gate][ttl-filter]")
{
    gate g{5353, 255, ttl_unknown_policy::accept, no_interfaces};
    CHECK(g.admit(with_ttl(std::nullopt), response));
}

TEST_CASE("packet_gate with ttl_unknown_policy::reject drops a response of unknown TTL", "[gate][ttl-filter]")
{
    gate g{5353, 255, ttl_unknown_policy::reject, no_interfaces};
    CHECK_FALSE(g.admit(with_ttl(std::nullopt), response));
}

TEST_CASE("packet_gate drops a response whose TTL is below receive_ttl_minimum", "[gate][ttl-filter]")
{
    gate g{5353, 255, ttl_unknown_policy::accept, no_interfaces};
    CHECK_FALSE(g.admit(with_ttl(uint8_t{10}), response));
}

TEST_CASE("packet_gate admits a response whose TTL is at or above receive_ttl_minimum", "[gate][ttl-filter]")
{
    gate g{5353, 255, ttl_unknown_policy::accept, no_interfaces};
    CHECK(g.admit(with_ttl(uint8_t{255}), response));
}

TEST_CASE("packet_gate admits a query whose TTL is below receive_ttl_minimum", "[gate][ttl-filter]")
{
    gate g{5353, 255, ttl_unknown_policy::accept, no_interfaces};
    CHECK(g.admit(with_ttl(uint8_t{1}), query));
    CHECK(g.admit(with_ttl(uint8_t{0}), query));
}

TEST_CASE("packet_gate admits a query of unknown TTL under ttl_unknown_policy::reject", "[gate][ttl-filter]")
{
    gate g{5353, 255, ttl_unknown_policy::reject, no_interfaces};
    CHECK(g.admit(with_ttl(std::nullopt), query));
}
