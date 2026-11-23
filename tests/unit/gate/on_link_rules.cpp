#include "interfaces.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/ip_address.h"
#include "mdnspp/mdns_options.h"

#include "mdnspp/detail/packet_gate.h"
#include "mdnspp/detail/ip_address_ops.h"

#include "mdnspp/inproc/inproc_policy.h"

#include "mdnspp/testing/test_clock.h"
#include "mdnspp/testing/mock_policy.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <optional>

using mdnspp::ttl_unknown_policy;

namespace {

template <typename P>
using gate = mdnspp::detail::packet_gate<P>;

std::vector<std::byte> response_header()
{
    std::vector<std::byte> packet(12, std::byte{0});
    packet[2] = std::byte{0x84};
    return packet;
}

interface_snapshot lan()
{
    return interface_snapshot{{
        nic_with(2, {network_of("192.0.2.1", 24), network_of("fe80::1", 64), network_of("2001:db8::1", 64)}),
        nic_with(3, {network_of("198.51.100.1", 24)}),
    }};
}

mdnspp::recv_metadata arriving(std::string source, std::optional<const char *> destination, uint32_t recv_ifindex,
                               std::optional<uint8_t> ttl = uint8_t{255})
{
    mdnspp::recv_metadata meta;
    meta.sender = mdnspp::endpoint{std::move(source), 5353};
    meta.ttl = ttl;
    meta.recv_ifindex = recv_ifindex;
    if(destination)
        meta.destination = mdnspp::detail::parse_ip_address(*destination);
    return meta;
}

template <typename P>
bool admitted(interface_snapshot &snapshot, const mdnspp::recv_metadata &meta)
{
    mdnspp::testing::test_clock::reset();
    gate<P> g{5353, 255, ttl_unknown_policy::accept, enumerate_from(snapshot)};
    return g.admit(meta, response_header());
}

using mock = mdnspp::testing::mock_policy;

}

TEST_CASE("a response of unknown destination passes only from an on-link source", "[gate][on-link]")
{
    interface_snapshot snapshot = lan();
    CHECK(admitted<mock>(snapshot, arriving("192.0.2.7", std::nullopt, 2)));
    CHECK_FALSE(admitted<mock>(snapshot, arriving("203.0.113.9", std::nullopt, 2)));
}

TEST_CASE("a response whose ancillary data was discarded passes only from an on-link source", "[gate][on-link]")
{
    interface_snapshot snapshot = lan();
    CHECK(admitted<mock>(snapshot, arriving("192.0.2.7", std::nullopt, 0, std::nullopt)));
    CHECK_FALSE(admitted<mock>(snapshot, arriving("203.0.113.9", std::nullopt, 0, std::nullopt)));
}

TEST_CASE("an IPv6 unicast response passes only from an on-link prefix of the receiving interface", "[gate][on-link]")
{
    interface_snapshot snapshot = lan();
    CHECK(admitted<mock>(snapshot, arriving("fe80::99%2", "2001:db8::1", 2)));
    CHECK(admitted<mock>(snapshot, arriving("2001:db8::77", "2001:db8::1", 2)));
    CHECK_FALSE(admitted<mock>(snapshot, arriving("2001:db8:1::5", "2001:db8::1", 2)));
    CHECK_FALSE(admitted<mock>(snapshot, arriving("fe80::99%3", "2001:db8::1", 3)));
}

TEST_CASE("a multicast response passes from an off-link source", "[gate][on-link]")
{
    interface_snapshot snapshot = lan();
    CHECK(admitted<mock>(snapshot, arriving("203.0.113.9", "224.0.0.251", 2)));
    CHECK(admitted<mock>(snapshot, arriving("2001:db8:1::5", "ff02::fb", 2)));
}

TEST_CASE("an in-process transport admits the off-link unicast response another transport drops", "[gate][on-link]")
{
    interface_snapshot snapshot = lan();
    const mdnspp::recv_metadata off_link = arriving("203.0.113.9", "192.0.2.1", 2);
    CHECK(admitted<mdnspp::inproc_test_policy>(snapshot, off_link));
    CHECK_FALSE(admitted<mock>(snapshot, off_link));
}
