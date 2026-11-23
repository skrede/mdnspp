#ifndef HPP_GUARD_MDNSPP_NETNS_HELPERS_H
#define HPP_GUARD_MDNSPP_NETNS_HELPERS_H

#include "support/netns.h"
#include "support/ipv6_interface.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <cstdint>
#include <fstream>
#include <sstream>

// /proc/net/igmp6 lists one membership per line: index, device, group in hex, users, flags, timer.
inline bool joined_mdns_group(const std::string &device)
{
    std::ifstream memberships{"/proc/net/igmp6"};
    std::string line;
    while(std::getline(memberships, line))
    {
        std::istringstream fields{line};
        std::string index, name, group;
        fields >> index >> name >> group;
        if(name == device && group == "ff0200000000000000000000000000fb")
            return true;
    }
    return false;
}

template <typename Socket>
void require_selected(Socket &socket, const std::string &device)
{
    const uint32_t expected = mdnspp::test_support::netns_interface_index(device);
    CHECK(mdnspp::test_support::ipv6_multicast_interface(socket.native_handle()) == expected);
    CHECK(joined_mdns_group(device));
    CHECK_FALSE(joined_mdns_group(device == "l1" ? "l0" : "l1"));
}

#endif
