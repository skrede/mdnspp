#include "mdnspp/detail/recv_ancillary.h"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <cstring>

using namespace mdnspp::detail;

namespace {

sockaddr_storage make_v4(const char *text, uint16_t port)
{
    sockaddr_storage storage{};
    auto &sa = reinterpret_cast<sockaddr_in &>(storage);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    ::inet_pton(AF_INET, text, &sa.sin_addr);
    return storage;
}

sockaddr_storage make_v6(const char *text, uint16_t port)
{
    sockaddr_storage storage{};
    auto &sa = reinterpret_cast<sockaddr_in6 &>(storage);
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    ::inet_pton(AF_INET6, text, &sa.sin6_addr);
    return storage;
}

}

TEST_CASE("endpoint_from_sockaddr renders an IPv4 sender", "[recv_ancillary]")
{
    const auto ep = endpoint_from_sockaddr(make_v4("192.0.2.1", 5353));

    REQUIRE(ep.address == "192.0.2.1");
    REQUIRE(ep.port == 5353);
}

TEST_CASE("endpoint_from_sockaddr renders an IPv6 sender", "[recv_ancillary]")
{
    const auto ep = endpoint_from_sockaddr(make_v6("2001:db8::1", 5353));

    REQUIRE(ep.address == "2001:db8::1");
    REQUIRE(ep.port == 5353);
}

#ifndef _WIN32

namespace {

class control_buffer
{
public:
    control_buffer()
        : m_storage{}
        , m_msg{}
        , m_used{0}
    {
        m_msg.msg_control = m_storage.data();
    }

    template <typename T>
    void add(int level, int type, const T &value)
    {
        auto *cmsg = reinterpret_cast<cmsghdr *>(m_storage.data() + m_used);
        cmsg->cmsg_level = level;
        cmsg->cmsg_type = type;
        cmsg->cmsg_len = CMSG_LEN(sizeof(T));
        std::memcpy(CMSG_DATA(cmsg), &value, sizeof(T));
        m_used += CMSG_SPACE(sizeof(T));
        m_msg.msg_controllen = m_used;
    }

    msghdr &message()
    {
        return m_msg;
    }

private:
    alignas(cmsghdr) std::array<std::byte, 256> m_storage;
    msghdr m_msg;
    std::size_t m_used;
};

}

TEST_CASE("parse_ancillary reads an int-sized IP_TTL", "[recv_ancillary]")
{
    for(const int ttl : {255, 1})
    {
        control_buffer control;
        control.add(IPPROTO_IP, IP_TTL, ttl);

        const ancillary_data data = parse_ancillary(control.message());

        REQUIRE(data.ttl == static_cast<uint8_t>(ttl));
        REQUIRE(data.ifindex == 0);
    }
}

#ifdef IPV6_HOPLIMIT
TEST_CASE("parse_ancillary reads an int-sized IPV6_HOPLIMIT", "[recv_ancillary]")
{
    control_buffer control;
    control.add(IPPROTO_IPV6, IPV6_HOPLIMIT, 255);

    const ancillary_data data = parse_ancillary(control.message());

    REQUIRE(data.ttl == 255);
    REQUIRE(data.ifindex == 0);
}
#endif

#ifdef IP_PKTINFO
TEST_CASE("parse_ancillary reads the interface index of IP_PKTINFO", "[recv_ancillary]")
{
    in_pktinfo info{};
    info.ipi_ifindex = 7;
    control_buffer control;
    control.add(IPPROTO_IP, IP_PKTINFO, info);

    const ancillary_data data = parse_ancillary(control.message());

    REQUIRE(data.ifindex == 7);
    REQUIRE_FALSE(data.ttl.has_value());
}
#endif

#ifdef IPV6_PKTINFO
TEST_CASE("parse_ancillary reads the interface index of IPV6_PKTINFO", "[recv_ancillary]")
{
    in6_pktinfo info{};
    info.ipi6_ifindex = 9;
    control_buffer control;
    control.add(IPPROTO_IPV6, IPV6_PKTINFO, info);

    const ancillary_data data = parse_ancillary(control.message());

    REQUIRE(data.ifindex == 9);
    REQUIRE_FALSE(data.ttl.has_value());
}
#endif

#if defined(IPV6_HOPLIMIT) && defined(IPV6_PKTINFO)
TEST_CASE("parse_ancillary combines the TTL and the interface index of one datagram", "[recv_ancillary]")
{
    in6_pktinfo info{};
    info.ipi6_ifindex = 4;
    control_buffer control;
    control.add(IPPROTO_IPV6, IPV6_HOPLIMIT, 255);
    control.add(IPPROTO_IPV6, IPV6_PKTINFO, info);

    const ancillary_data data = parse_ancillary(control.message());

    REQUIRE(data.ttl == 255);
    REQUIRE(data.ifindex == 4);
}
#endif

TEST_CASE("parse_ancillary yields no TTL and interface zero for an empty control buffer", "[recv_ancillary]")
{
    control_buffer control;

    const ancillary_data data = parse_ancillary(control.message());

    REQUIRE_FALSE(data.ttl.has_value());
    REQUIRE(data.ifindex == 0);
}

#endif
