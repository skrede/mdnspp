#include "mdnspp/detail/ip_address_ops.h"
#include "mdnspp/detail/recv_ancillary.h"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

using namespace mdnspp::detail;

namespace {

class wsa_control
{
public:
    wsa_control()
        : m_storage{}
        , m_msg{}
        , m_used{0}
    {
        m_msg.Control.buf = reinterpret_cast<CHAR *>(m_storage.data());
    }

    wsa_control(const wsa_control &) = delete;
    wsa_control &operator=(const wsa_control &) = delete;

    template <typename T>
    void add(int32_t level, int32_t type, const T &value)
    {
        REQUIRE(m_used + WSA_CMSG_SPACE(sizeof(T)) <= m_storage.size());
        auto *cmsg = reinterpret_cast<WSACMSGHDR *>(m_storage.data() + m_used);
        cmsg->cmsg_level = level;
        cmsg->cmsg_type = type;
        cmsg->cmsg_len = WSA_CMSG_LEN(sizeof(T));
        std::memcpy(WSA_CMSG_DATA(cmsg), &value, sizeof(T));
        m_used += WSA_CMSG_SPACE(sizeof(T));
        m_msg.Control.len = static_cast<ULONG>(m_used);
    }

    void truncate() { m_msg.dwFlags |= MSG_CTRUNC; }

    WSAMSG &message() { return m_msg; }

private:
    alignas(WSACMSGHDR) std::array<std::byte, 256> m_storage;
    WSAMSG m_msg;
    std::size_t m_used;
};

IN_PKTINFO pktinfo_v4(const char *destination, uint32_t index)
{
    IN_PKTINFO info{};
    info.ipi_ifindex = static_cast<ULONG>(index);
    ::inet_pton(AF_INET, destination, &info.ipi_addr);
    return info;
}

IN6_PKTINFO pktinfo_v6(const char *destination, uint32_t index)
{
    IN6_PKTINFO info{};
    info.ipi6_ifindex = static_cast<ULONG>(index);
    ::inet_pton(AF_INET6, destination, &info.ipi6_addr);
    return info;
}

}

TEST_CASE("parse_ancillary reads the IPv4 TTL, interface and destination from a WSAMSG", "[recv_ancillary][windows]")
{
    wsa_control control;
    control.add(IPPROTO_IP, IP_TTL, int32_t{255});
    control.add(IPPROTO_IP, IP_PKTINFO, pktinfo_v4("224.0.0.251", 9));

    const ancillary_data data = parse_ancillary(control.message());

    REQUIRE(data.ttl == 255);
    REQUIRE(data.ifindex == 9);
    REQUIRE(data.destination == parse_ip_address("224.0.0.251"));
}

TEST_CASE("parse_ancillary reads the IPv6 hop limit, interface and destination from a WSAMSG",
          "[recv_ancillary][windows]")
{
    wsa_control control;
    control.add(IPPROTO_IPV6, IPV6_HOPLIMIT, int32_t{255});
    control.add(IPPROTO_IPV6, IPV6_PKTINFO, pktinfo_v6("ff02::fb", 11));

    const ancillary_data data = parse_ancillary(control.message());

    REQUIRE(data.ttl == 255);
    REQUIRE(data.ifindex == 11);
    REQUIRE(data.destination == parse_ip_address("ff02::fb"));
}

TEST_CASE("parse_ancillary reports nothing from a truncated WSAMSG control buffer", "[recv_ancillary][windows]")
{
    wsa_control control;
    control.add(IPPROTO_IP, IP_TTL, int32_t{255});
    control.add(IPPROTO_IP, IP_PKTINFO, pktinfo_v4("224.0.0.251", 9));
    control.truncate();

    const ancillary_data data = parse_ancillary(control.message());

    REQUIRE_FALSE(data.ttl.has_value());
    REQUIRE(data.ifindex == 0);
    REQUIRE_FALSE(data.destination.has_value());
}

TEST_CASE("parse_ancillary ignores a WSAMSG message whose payload is shorter than its type",
          "[recv_ancillary][windows]")
{
    wsa_control control;
    control.add(IPPROTO_IP, IP_PKTINFO, uint8_t{1});

    const ancillary_data data = parse_ancillary(control.message());

    REQUIRE(data.ifindex == 0);
    REQUIRE_FALSE(data.destination.has_value());
}
