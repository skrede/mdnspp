#include "mdnspp/ip_address.h"

#include "mdnspp/detail/ip_address_ops.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

using mdnspp::ip_address;
using mdnspp::address_family;
using mdnspp::detail::in_prefix;
using mdnspp::detail::parse_ip_address;
using mdnspp::detail::format_ip_address;

namespace {

ip_address address(std::string_view text)
{
    const std::optional<ip_address> parsed = parse_ip_address(text);
    REQUIRE(parsed.has_value());
    return *parsed;
}

bool contains(std::string_view prefix, uint8_t length, std::string_view text)
{
    return in_prefix(address(text), address(prefix), length);
}

}

TEST_CASE("IPv4 multicast is exactly the class D range", "[ip_address]")
{
    REQUIRE_FALSE(address("223.255.255.255").is_multicast());
    REQUIRE(address("224.0.0.0").is_multicast());
    REQUIRE(address("224.0.0.251").is_multicast());
    REQUIRE(address("239.255.255.255").is_multicast());
    REQUIRE_FALSE(address("240.0.0.0").is_multicast());
    REQUIRE_FALSE(address("127.0.0.1").is_multicast());
}

TEST_CASE("IPv6 multicast is the ff00::/8 range", "[ip_address]")
{
    REQUIRE(address("ff02::fb").is_multicast());
    REQUIRE_FALSE(address("fe80::1").is_multicast());
    REQUIRE_FALSE(address("::1").is_multicast());
}

TEST_CASE("an IPv4 address uses the first four bytes and leaves the rest zero", "[ip_address]")
{
    const ip_address parsed = address("192.0.2.1");

    REQUIRE(parsed.family == address_family::ipv4);
    REQUIRE(std::to_integer<uint8_t>(parsed.bytes[0]) == 192);
    REQUIRE(std::to_integer<uint8_t>(parsed.bytes[3]) == 1);
    for(std::size_t i = 4; i < parsed.bytes.size(); ++i)
        REQUIRE(std::to_integer<uint8_t>(parsed.bytes[i]) == 0);
}

TEST_CASE("ip_address equality compares the family and every byte", "[ip_address]")
{
    REQUIRE(address("192.0.2.1") == address("192.0.2.1"));
    REQUIRE_FALSE(address("192.0.2.1") == address("192.0.2.2"));
    REQUIRE(ip_address{} == ip_address{.family = address_family::ipv4});
    REQUIRE_FALSE(ip_address{.family = address_family::ipv4} == ip_address{.family = address_family::ipv6});
}

TEST_CASE("in_prefix matches IPv4 prefixes on whole and partial bytes", "[ip_address]")
{
    REQUIRE(contains("0.0.0.0", 0, "203.0.113.9"));
    REQUIRE(contains("192.0.2.0", 24, "192.0.2.77"));
    REQUIRE_FALSE(contains("192.0.2.0", 24, "192.0.3.77"));
    REQUIRE(contains("192.0.2.1", 32, "192.0.2.1"));
    REQUIRE_FALSE(contains("192.0.2.1", 32, "192.0.2.2"));
    REQUIRE(contains("198.51.100.0", 23, "198.51.101.5"));
    REQUIRE_FALSE(contains("198.51.100.0", 23, "198.51.102.5"));
}

TEST_CASE("in_prefix matches IPv6 prefixes on whole and partial bytes", "[ip_address]")
{
    REQUIRE(contains("::", 0, "2001:db8::1"));
    REQUIRE(contains("fe80::", 10, "febf::1"));
    REQUIRE_FALSE(contains("fe80::", 10, "fec0::1"));
    REQUIRE(contains("2001:db8:0:80::", 57, "2001:db8:0:ff::1"));
    REQUIRE_FALSE(contains("2001:db8:0:80::", 57, "2001:db8:0:7f::1"));
    REQUIRE(contains("2001:db8:1:2::", 64, "2001:db8:1:2:aaaa::1"));
    REQUIRE_FALSE(contains("2001:db8:1:2::", 64, "2001:db8:1:3::1"));
    REQUIRE(contains("2001:db8::1", 128, "2001:db8::1"));
    REQUIRE_FALSE(contains("2001:db8::1", 128, "2001:db8::2"));
}

TEST_CASE("in_prefix rejects a family mismatch and an over-long length", "[ip_address]")
{
    REQUIRE_FALSE(in_prefix(ip_address{.family = address_family::ipv4}, ip_address{.family = address_family::ipv6}, 0));
    REQUIRE_FALSE(contains("192.0.2.1", 33, "192.0.2.1"));
    REQUIRE_FALSE(contains("2001:db8::1", 129, "2001:db8::1"));
}

TEST_CASE("parse_ip_address and format_ip_address round trip both families", "[ip_address]")
{
    for(const std::string_view text : {"192.0.2.1", "224.0.0.251", "127.0.0.1", "2001:db8::1", "ff02::fb", "::1"})
        REQUIRE(format_ip_address(address(text)) == std::string{text});

    REQUIRE(address("2001:db8::1").family == address_family::ipv6);
    REQUIRE(address("192.0.2.1").family == address_family::ipv4);
}

TEST_CASE("parse_ip_address drops an IPv6 zone suffix", "[ip_address]")
{
    REQUIRE(address("fe80::1%1") == address("fe80::1"));
    REQUIRE(format_ip_address(address("fe80::1%1")) == "fe80::1");
}

TEST_CASE("parse_ip_address rejects text that is not an address", "[ip_address]")
{
    for(const std::string_view text : {"", "mdns.local", "256.0.0.1", "192.0.2", "::g", "fe80::1%"})
        REQUIRE_FALSE(parse_ip_address(text).has_value());
}
