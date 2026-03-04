#include "mdnspp/mdns_util.h"

std::string mdnspp::ip_address_to_string(const sockaddr *addr, size_t addrlen)
{
    char host[NI_MAXHOST]   = {};
    char service[NI_MAXSERV] = {};
    int ret = getnameinfo(addr, static_cast<socklen_t>(addrlen),
                          host, NI_MAXHOST,
                          service, NI_MAXSERV,
                          NI_NUMERICSERV | NI_NUMERICHOST);
    if (ret != 0)
        return {};

    if (addr->sa_family == AF_INET6)
    {
        auto *in6 = reinterpret_cast<const sockaddr_in6 *>(addr);
        if (in6->sin6_port != 0)
            return std::string("[") + host + "]:" + service;
        return host;
    }

    auto *in4 = reinterpret_cast<const sockaddr_in *>(addr);
    if (in4->sin_port != 0)
        return std::string(host) + ":" + service;
    return host;
}

std::string mdnspp::ip_address_to_string(const sockaddr_in &addr)
{
    return ip_address_to_string(
        reinterpret_cast<const sockaddr *>(&addr), sizeof(sockaddr_in));
}

std::string mdnspp::ip_address_to_string(const sockaddr_in6 &addr)
{
    return ip_address_to_string(
        reinterpret_cast<const sockaddr *>(&addr), sizeof(sockaddr_in6));
}
