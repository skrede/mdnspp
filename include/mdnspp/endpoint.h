#ifndef MDNSPP_ENDPOINT_H
#define MDNSPP_ENDPOINT_H

#include <cstdint>
#include <string>
#include <ostream>

namespace mdnspp {

struct endpoint
{
    std::string address;   // "192.168.1.1" or "fe80::1"
    uint16_t    port{0};

    bool operator==(const endpoint&) const = default;
};

inline std::ostream& operator<<(std::ostream& str, const endpoint& ep)
{
    str << ep.address << ":" << ep.port;
    return str;
}

} // namespace mdnspp

#endif // MDNSPP_ENDPOINT_H
