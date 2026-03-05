#ifndef HPP_GUARD_MDNSPP_ENDPOINT_H
#define HPP_GUARD_MDNSPP_ENDPOINT_H

#include <compare>
#include <cstdint>
#include <ostream>
#include <string>

namespace mdnspp {

struct endpoint
{
    std::string address; // "192.168.1.1" or "fe80::1"
    uint16_t port{0};

    auto operator<=>(const endpoint &) const = default;
};

inline std::ostream &operator<<(std::ostream &str, const endpoint &ep)
{
    str << ep.address << ":" << ep.port;
    return str;
}

}

#endif
