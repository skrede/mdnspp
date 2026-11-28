#include "support/control_buffer.h"

#include "mdnspp/detail/ip_address_ops.h"
#include "mdnspp/detail/recv_ancillary.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <cstddef>
#include <cstdint>

using namespace mdnspp::detail;
using mdnspp::test_support::control_buffer;

namespace {

#ifdef IP_PKTINFO
in_pktinfo pktinfo_v4(const char *destination, uint32_t index)
{
    in_pktinfo info{};
    info.ipi_ifindex = static_cast<decltype(info.ipi_ifindex)>(index);
    ::inet_pton(AF_INET, destination, &info.ipi_addr);
    return info;
}
#endif

#ifdef IPV6_PKTINFO
in6_pktinfo pktinfo_v6(const char *destination, uint32_t index)
{
    in6_pktinfo info{};
    info.ipi6_ifindex = static_cast<decltype(info.ipi6_ifindex)>(index);
    ::inet_pton(AF_INET6, destination, &info.ipi6_addr);
    return info;
}
#endif

}

#ifdef IP_PKTINFO
TEST_CASE("parse_ancillary reads the destination and interface of IP_PKTINFO", "[recv_ancillary][destination]")
{
    control_buffer control;
    control.add(IPPROTO_IP, IP_PKTINFO, pktinfo_v4("224.0.0.251", 3));

    const ancillary_data data = parse_ancillary(control.message());

    REQUIRE(data.destination == parse_ip_address("224.0.0.251"));
    REQUIRE(data.ifindex == 3);
}
#endif

#ifdef IPV6_PKTINFO
TEST_CASE("parse_ancillary reads the destination and interface of IPV6_PKTINFO", "[recv_ancillary][destination]")
{
    control_buffer control;
    control.add(IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_v6("ff02::fb", 5));

    const ancillary_data data = parse_ancillary(control.message());

    REQUIRE(data.destination == parse_ip_address("ff02::fb"));
    REQUIRE(data.ifindex == 5);
}

TEST_CASE("parse_ancillary leaves the destination unknown for a short packet info payload",
          "[recv_ancillary][destination]")
{
    const in6_pktinfo info = pktinfo_v6("ff02::fb", 5);
    const auto bytes = std::as_bytes(std::span<const in6_pktinfo, 1>{&info, 1});
    control_buffer control;
    control.add_raw(IPPROTO_IPV6, IPV6_PKTINFO, bytes.first(sizeof(info) - 1));

    const ancillary_data data = parse_ancillary(control.message());

    REQUIRE_FALSE(data.destination.has_value());
    REQUIRE(data.ifindex == 0);
}
#endif

#if defined(IPV6_HOPLIMIT) && defined(IPV6_PKTINFO)
TEST_CASE("parse_ancillary discards destination, interface and TTL of a truncated control buffer",
          "[recv_ancillary][destination]")
{
    control_buffer control;
    control.add(IPPROTO_IPV6, IPV6_HOPLIMIT, 255);
    control.add(IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_v6("ff02::fb", 5));
#ifdef IP_PKTINFO
    control.add(IPPROTO_IP, IP_PKTINFO, pktinfo_v4("224.0.0.251", 3));
#endif
    control.set_flags(MSG_CTRUNC);

    const ancillary_data data = parse_ancillary(control.message());

    REQUIRE_FALSE(data.destination.has_value());
    REQUIRE(data.ifindex == 0);
    REQUIRE_FALSE(data.ttl.has_value());
}
#endif
