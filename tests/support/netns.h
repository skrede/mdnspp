#ifndef HPP_GUARD_MDNSPP_SUPPORT_NETNS_H
#define HPP_GUARD_MDNSPP_SUPPORT_NETNS_H

#include <catch2/catch_test_macros.hpp>

#include <fcntl.h>
#include <sched.h>
#include <unistd.h>

#include <net/if.h>

#include <netinet/in.h>

#include <sys/socket.h>

#include <cerrno>
#include <string>
#include <thread>
#include <cstdint>
#include <cstdlib>
#include <cstring>
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
inline int32_t open_udp_socket_in_netns(const std::string &netns, int32_t family)
{
    int32_t fd = -1;
    int32_t error = 0;
    std::thread worker{[&]
    {
        const int32_t ns = ::open(("/run/netns/" + netns).c_str(), O_RDONLY | O_CLOEXEC);
        if(ns >= 0 && ::setns(ns, CLONE_NEWNET) == 0)
            fd = ::socket(family, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
        error = fd < 0 ? errno : 0;
        if(ns >= 0)
            ::close(ns);
    }};
    worker.join();
    INFO("socket in namespace " << netns << ": " << std::strerror(error));
    REQUIRE(fd >= 0);
    return fd;
}

}

#endif
