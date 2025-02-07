#include "mdnspp/mdns_util.h"

#include <mdns.h>

std::string mdnspp::ip_address_to_string(const sockaddr *addr, size_t addrlen)
{
    char addr_buffer[1024];
    mdns_string_t str;
    if(addr->sa_family == AF_INET6)
        str = mdnspp::ipv6_address_to_string(addr_buffer, sizeof(addr_buffer), reinterpret_cast<const sockaddr_in6*>(addr), addrlen);
    else
        str = mdnspp::ipv4_address_to_string(addr_buffer, sizeof(addr_buffer), reinterpret_cast<const sockaddr_in*>(addr), addrlen);
    return {str.str, str.length};
}

std::string mdnspp::ip_address_to_string(const sockaddr_in &addr)
{
    char addr_buffer[1024];
    mdns_string_t str = mdnspp::ipv4_address_to_string(addr_buffer, sizeof(addr_buffer), &addr, sizeof(sockaddr_in));
    return {str.str, str.length};
}

std::string mdnspp::ip_address_to_string(const sockaddr_in6 &addr)
{
    char addr_buffer[1024];
    mdns_string_t str = mdnspp::ipv6_address_to_string(addr_buffer, sizeof(addr_buffer), &addr, sizeof(sockaddr_in6));
    return {str.str, str.length};
}

mdns_string_t mdnspp::ipv4_address_to_string(char *buffer, size_t capacity, const sockaddr_in *addr, size_t addrlen)
{
    char host[NI_MAXHOST] = {0};
    char service[NI_MAXSERV] = {0};
    int ret = getnameinfo(reinterpret_cast<const sockaddr*>(addr), addrlen, host, NI_MAXHOST, service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
    int len = 0;
    if(ret == 0)
    {
        if(addr->sin_port != 0)
            len = snprintf(buffer, capacity, "%s:%s", host, service);
        else
            len = snprintf(buffer, capacity, "%s", host);
    }
    if(len >= (int)capacity)
        len = (int)capacity - 1;
    mdns_string_t str;
    str.str = buffer;
    str.length = len;
    return str;
}

mdns_string_t mdnspp::ipv6_address_to_string(char *buffer, size_t capacity, const sockaddr_in6 *addr, size_t addrlen)
{
    char host[NI_MAXHOST] = {0};
    char service[NI_MAXSERV] = {0};
    int ret = getnameinfo(reinterpret_cast<const sockaddr*>(addr), addrlen, host, NI_MAXHOST, service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
    int len = 0;
    if(ret == 0)
    {
        if(addr->sin6_port != 0)
            len = snprintf(buffer, capacity, "[%s]:%s", host, service);
        else
            len = snprintf(buffer, capacity, "%s", host);
    }
    if(len >= (int)capacity)
        len = (int)capacity - 1;
    mdns_string_t str;
    str.str = buffer;
    str.length = len;
    return str;
}