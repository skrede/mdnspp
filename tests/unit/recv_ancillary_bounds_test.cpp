#include "support/control_buffer.h"

#include "mdnspp/detail/recv_ancillary.h"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>

using namespace mdnspp::detail;
using mdnspp::test_support::control_buffer;

TEST_CASE("parse_ancillary ignores an IP_TTL payload shorter than an int", "[recv_ancillary]")
{
    const std::array<std::byte, 1> payload{std::byte{64}};
    control_buffer control;
    control.add_raw(IPPROTO_IP, IP_TTL, payload);

    const ancillary_data data = parse_ancillary(control.message());

    REQUIRE_FALSE(data.ttl.has_value());
}

#ifdef IP_PKTINFO
TEST_CASE("parse_ancillary ignores an IP_PKTINFO payload shorter than in_pktinfo", "[recv_ancillary]")
{
    const int32_t ifindex = 7;
    control_buffer control;
    control.add(IPPROTO_IP, IP_PKTINFO, ifindex);

    const ancillary_data data = parse_ancillary(control.message());

    REQUIRE(data.ifindex == 0);
}
#endif

TEST_CASE("parse_ancillary reports no TTL and interface zero for truncated control data", "[recv_ancillary]")
{
    control_buffer control;
    control.add(IPPROTO_IP, IP_TTL, int32_t{255});
#ifdef IP_PKTINFO
    in_pktinfo info{};
    info.ipi_ifindex = 3;
    control.add(IPPROTO_IP, IP_PKTINFO, info);
#endif
    control.set_flags(MSG_CTRUNC);

    const ancillary_data data = parse_ancillary(control.message());

    REQUIRE_FALSE(data.ttl.has_value());
    REQUIRE(data.ifindex == 0);
}

#if defined(__APPLE__) && defined(IP_RECVTTL)
TEST_CASE("parse_ancillary reads the one-byte IP_RECVTTL payload", "[recv_ancillary]")
{
    const std::array<std::byte, 1> payload{std::byte{255}};
    control_buffer control;
    control.add_raw(IPPROTO_IP, IP_RECVTTL, payload);

    const ancillary_data data = parse_ancillary(control.message());

    REQUIRE(data.ttl == 255);
}
#endif
