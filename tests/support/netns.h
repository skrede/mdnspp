#ifndef HPP_GUARD_MDNSPP_SUPPORT_NETNS_H
#define HPP_GUARD_MDNSPP_SUPPORT_NETNS_H

#include "mdnspp/endpoint.h"

#include "mdnspp/detail/native_sockaddr.h"

#include <catch2/catch_test_macros.hpp>

#include <fcntl.h>
#include <sched.h>
#include <unistd.h>

#include <net/if.h>

#include <netinet/in.h>

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <cerrno>
#include <string>
#include <thread>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string_view>

namespace mdnspp::test_support {

// tests/netns/run.sh sets MDNSPP_REQUIRE_NETNS, so a missing topology fails there instead of skipping.
inline void netns_or_fail(std::string_view reason)
{
    const char *required = std::getenv("MDNSPP_REQUIRE_NETNS");
    if(required != nullptr && *required != '\0')
        FAIL(reason);
    SKIP(reason);
}

inline uint32_t netns_interface_index(const std::string &name)
{
    return ::if_nametoindex(name.c_str());
}

inline void require_netns_harness()
{
    const bool inside = netns_interface_index("d0") != 0 && netns_interface_index("l1") != 0 &&
                        ::access("/run/netns/p1", F_OK) == 0;
    if(!inside)
        netns_or_fail("not running inside the tests/netns/run.sh topology");
}

// A network namespace belongs to a thread, and a socket keeps the namespace it was created in.
template <typename Work>
void run_in_netns(const std::string &netns, Work work)
{
    bool entered = false;
    std::thread worker{[&]
    {
        const int32_t ns = ::open(("/run/netns/" + netns).c_str(), O_RDONLY | O_CLOEXEC);
        entered = ns >= 0 && ::setns(ns, CLONE_NEWNET) == 0;
        if(entered)
            work();
        if(ns >= 0)
            ::close(ns);
    }};
    worker.join();
    INFO("entering namespace " << netns);
    REQUIRE(entered);
}

inline int32_t open_udp_socket_in_netns(const std::string &netns, int32_t family)
{
    int32_t fd = -1;
    int32_t error = 0;
    run_in_netns(netns, [&]
    {
        fd = ::socket(family, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
        error = fd < 0 ? errno : 0;
    });
    INFO("socket in namespace " << netns << ": " << std::strerror(error));
    REQUIRE(fd >= 0);
    return fd;
}

// SIOCGIFINDEX resolves the name in the socket's namespace, where if_nametoindex would use the calling thread's.
inline uint32_t device_index_of(int32_t fd, const std::string &device)
{
    ifreq request{};
    device.copy(request.ifr_name, IFNAMSIZ - 1);
    REQUIRE(::ioctl(fd, SIOCGIFINDEX, &request) == 0);
    return static_cast<uint32_t>(request.ifr_ifindex);
}

inline void send_multicast_out_of(int32_t fd, int32_t family, uint32_t device_index)
{
    const int32_t hops = 255;
    if(family == AF_INET6)
    {
        REQUIRE(::setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &device_index, sizeof(device_index)) == 0);
        REQUIRE(::setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof(hops)) == 0);
        return;
    }
    ip_mreqn request{};
    request.imr_ifindex = static_cast<int32_t>(device_index);
    REQUIRE(::setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &request, sizeof(request)) == 0);
    REQUIRE(::setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &hops, sizeof(hops)) == 0);
}

inline int32_t open_multicast_sender_in_netns(const std::string &netns, const std::string &device,
                                              const endpoint &source)
{
    const std::optional<detail::sockaddr_result> local = detail::build_sockaddr(source);
    REQUIRE(local.has_value());
    const int32_t family = local->ss.ss_family;
    const int32_t fd = open_udp_socket_in_netns(netns, family);
    REQUIRE(::bind(fd, reinterpret_cast<const sockaddr *>(&local->ss), local->len) == 0);
    send_multicast_out_of(fd, family, device_index_of(fd, device));
    return fd;
}

}

#endif
