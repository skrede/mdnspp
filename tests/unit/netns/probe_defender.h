#ifndef HPP_GUARD_MDNSPP_NETNS_PROBE_DEFENDER_H
#define HPP_GUARD_MDNSPP_NETNS_PROBE_DEFENDER_H

#include "netns/bound_peers.h"
#include "netns/grouped_pair.h"

#include "support/netns.h"

#include "mdnspp/detail/dns_response.h"
#include "mdnspp/detail/native_sockaddr.h"
#include "mdnspp/detail/server_question_section.h"

#include <unistd.h>

#include <netinet/in.h>

#include <sys/socket.h>

#include <array>
#include <chrono>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <optional>

struct defense_family
{
    int32_t family;
    std::string group;
    std::string wildcard;
    std::string source_prefix;
};

struct heard_probe
{
    mdnspp::detail::sockaddr_result from;
    bool wants_unicast;
};

struct defense_round
{
    bool probe_heard;
    bool d0_conflict;
    bool d1_conflict;
};

inline mdnspp::detail::sockaddr_result resolved(const std::string &address)
{
    const std::optional<mdnspp::detail::sockaddr_result> result =
        mdnspp::detail::build_sockaddr(mdnspp::endpoint{address, mdns_port});
    REQUIRE(result.has_value());
    return *result;
}

inline void bind_reusable(int32_t fd, const std::string &address)
{
    const int32_t on = 1;
    REQUIRE(::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) == 0);
    const mdnspp::detail::sockaddr_result local = resolved(address);
    REQUIRE(::bind(fd, reinterpret_cast<const sockaddr *>(&local.ss), local.len) == 0);
}

inline void join_group(int32_t fd, const defense_family &family, uint32_t device_index)
{
    const mdnspp::detail::sockaddr_result group = resolved(family.group);
    if(family.family == AF_INET6)
    {
        ipv6_mreq request{};
        request.ipv6mr_multiaddr = reinterpret_cast<const sockaddr_in6 &>(group.ss).sin6_addr;
        request.ipv6mr_interface = device_index;
        REQUIRE(::setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &request, sizeof(request)) == 0);
        return;
    }
    ip_mreqn request{};
    request.imr_multiaddr = reinterpret_cast<const sockaddr_in &>(group.ss).sin_addr;
    request.imr_ifindex = static_cast<int32_t>(device_index);
    REQUIRE(::setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &request, sizeof(request)) == 0);
}

inline int32_t open_defender_listener(const defense_family &family)
{
    const int32_t fd = mdnspp::test_support::open_udp_socket_in_netns("p0", family.family);
    bind_reusable(fd, family.wildcard);
    join_group(fd, family, mdnspp::test_support::device_index_of(fd, "q0"));
    return fd;
}

inline std::optional<heard_probe> hear_probe(int32_t fd)
{
    std::array<std::byte, 1500> packet{};
    heard_probe heard{{}, false};
    heard.from.len = sizeof(heard.from.ss);
    const ssize_t got = ::recvfrom(fd, packet.data(), packet.size(), MSG_DONTWAIT,
                                   reinterpret_cast<sockaddr *>(&heard.from.ss), &heard.from.len);
    if(got < 12 || (std::to_integer<uint8_t>(packet[2]) & 0x80) != 0)
        return std::nullopt;
    std::size_t offset = 12;
    const auto question = mdnspp::detail::read_question({packet.data(), static_cast<std::size_t>(got)}, offset);
    if(!question.has_value())
        return std::nullopt;
    heard.wants_unicast = (question->qclass & 0x8000) != 0;
    return heard;
}

inline void send_conflicting_srv(int32_t fd, const mdnspp::detail::sockaddr_result &to)
{
    mdnspp::service_info other = grouped_service();
    other.port = 9090;
    const std::vector<std::byte> packet =
        mdnspp::detail::build_dns_response(other, mdnspp::dns_type::srv, mdnspp::service_options{});
    const ssize_t sent = ::sendto(fd, packet.data(), packet.size(), 0, reinterpret_cast<const sockaddr *>(&to.ss),
                                  to.len);
    REQUIRE(sent == static_cast<ssize_t>(packet.size()));
}

inline void answer_probe(const defense_family &family, const std::string &source, const heard_probe &heard)
{
    const int32_t fd = mdnspp::test_support::open_udp_socket_in_netns("p0", family.family);
    bind_reusable(fd, source);
    const int32_t hops = 255;
    if(family.family == AF_INET6)
        REQUIRE(::setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &hops, sizeof(hops)) == 0);
    else
        REQUIRE(::setsockopt(fd, IPPROTO_IP, IP_TTL, &hops, sizeof(hops)) == 0);
    mdnspp::detail::sockaddr_result to = heard.from;
    if(!heard.wants_unicast)
    {
        mdnspp::test_support::send_multicast_out_of(fd, family.family,
                                                    mdnspp::test_support::device_index_of(fd, "q0"));
        to = resolved(family.group);
    }
    send_conflicting_srv(fd, to);
    ::close(fd);
}

inline std::optional<heard_probe> await_probe(mdnspp::default_context &ctx, int32_t listener)
{
    for(uint32_t slice = 0; slice < 50; ++slice)
    {
        run_for(ctx, std::chrono::milliseconds{20});
        if(const std::optional<heard_probe> heard = hear_probe(listener))
            return heard;
    }
    return std::nullopt;
}

inline defense_round run_defense_round(const defense_family &family, const std::string &source)
{
    mdnspp::default_context ctx;
    const int32_t listener = open_defender_listener(family);
    grouped_pair pair{ctx, family.group};
    const std::optional<heard_probe> heard = await_probe(ctx, listener);
    if(heard.has_value())
    {
        answer_probe(family, source, *heard);
        run_for(ctx, std::chrono::milliseconds{300});
    }
    ::close(listener);
    return defense_round{heard.has_value(), pair.d0_conflict(), pair.d1_conflict()};
}

#endif
