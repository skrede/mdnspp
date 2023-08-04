#include "mdnspp/mdns_util.h"

#include <mdns.h>

static int has_ipv4;
static int has_ipv6;

mdns_string_t mdnspp::ipv4_address_to_string(char *buffer, size_t capacity, const struct sockaddr_in *addr, size_t addrlen)
{
    char host[NI_MAXHOST] = {0};
    char service[NI_MAXSERV] = {0};
    int ret = getnameinfo((const struct sockaddr *) addr, (socklen_t) addrlen, host, NI_MAXHOST,
                          service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
    int len = 0;
    if(ret == 0)
    {
        if(addr->sin_port != 0)
            len = snprintf(buffer, capacity, "%s:%s", host, service);
        else
            len = snprintf(buffer, capacity, "%s", host);
    }
    if(len >= (int) capacity)
        len = (int) capacity - 1;
    mdns_string_t str;
    str.str = buffer;
    str.length = len;
    return str;
}

mdns_string_t mdnspp::ipv6_address_to_string(char *buffer, size_t capacity, const struct sockaddr_in6 *addr, size_t addrlen)
{
    char host[NI_MAXHOST] = {0};
    char service[NI_MAXSERV] = {0};
    int ret = getnameinfo((const struct sockaddr *) addr, (socklen_t) addrlen, host, NI_MAXHOST,
                          service, NI_MAXSERV, NI_NUMERICSERV | NI_NUMERICHOST);
    int len = 0;
    if(ret == 0)
    {
        if(addr->sin6_port != 0)
            len = snprintf(buffer, capacity, "[%s]:%s", host, service);
        else
            len = snprintf(buffer, capacity, "%s", host);
    }
    if(len >= (int) capacity)
        len = (int) capacity - 1;
    mdns_string_t str;
    str.str = buffer;
    str.length = len;
    return str;
}

mdns_string_t mdnspp::ip_address_to_string(char *buffer, size_t capacity, const struct sockaddr *addr, size_t addrlen)
{
    if(addr->sa_family == AF_INET6)
        return ipv6_address_to_string(buffer, capacity, (const struct sockaddr_in6 *) addr, addrlen);
    return ipv4_address_to_string(buffer, capacity, (const struct sockaddr_in *) addr, addrlen);
}

// Open sockets for sending one-shot multicast queries from an ephemeral port
int mdnspp::open_client_sockets(int *sockets, int max_sockets, int port, sockaddr_in &service_address_ipv4, sockaddr_in6 &service_address_ipv6)
{
    // When sending, each socket can only send to one network interface
    // Thus we need to open one socket for each interface and address family
    int num_sockets = 0;

#ifdef _WIN32

    IP_ADAPTER_ADDRESSES* adapter_address = 0;
    ULONG address_size = 8000;
    unsigned int ret;
    unsigned int num_retries = 4;
    do {
        adapter_address = (IP_ADAPTER_ADDRESSES*)malloc(address_size);
        ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, 0,
                                   adapter_address, &address_size);
        if (ret == ERROR_BUFFER_OVERFLOW) {
            free(adapter_address);
            adapter_address = 0;
            address_size *= 2;
        } else {
            break;
        }
    } while (num_retries-- > 0);

    if (!adapter_address || (ret != NO_ERROR)) {
        free(adapter_address);
        printf("Failed to get network adapter addresses\n");
        return num_sockets;
    }

    int first_ipv4 = 1;
    int first_ipv6 = 1;
    for (PIP_ADAPTER_ADDRESSES adapter = adapter_address; adapter; adapter = adapter->Next) {
        if (adapter->TunnelType == TUNNEL_TYPE_TEREDO)
            continue;
        if (adapter->OperStatus != IfOperStatusUp)
            continue;

        for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress; unicast;
             unicast = unicast->Next) {
            if (unicast->Address.lpSockaddr->sa_family == AF_INET) {
                struct sockaddr_in* saddr = (struct sockaddr_in*)unicast->Address.lpSockaddr;
                if ((saddr->sin_addr.S_un.S_un_b.s_b1 != 127) ||
                    (saddr->sin_addr.S_un.S_un_b.s_b2 != 0) ||
                    (saddr->sin_addr.S_un.S_un_b.s_b3 != 0) ||
                    (saddr->sin_addr.S_un.S_un_b.s_b4 != 1)) {
                    int log_addr = 0;
                    if (first_ipv4) {
                        service_address_ipv4 = *saddr;
                        first_ipv4 = 0;
                        log_addr = 1;
                    }
                    has_ipv4 = 1;
                    if (num_sockets < max_sockets) {
                        saddr->sin_port = htons((unsigned short)port);
                        int sock = mdns_socket_open_ipv4(saddr);
                        if (sock >= 0) {
                            sockets[num_sockets++] = sock;
                            log_addr = 1;
                        } else {
                            log_addr = 0;
                        }
                    }
                    if (log_addr) {
                        char buffer[128];
                        mdns_string_t addr = ipv4_address_to_string(buffer, sizeof(buffer), saddr,
                                                                    sizeof(struct sockaddr_in));
                        printf("Local IPv4 address: %.*s\n", MDNS_STRING_FORMAT(addr));
                    }
                }
            } else if (unicast->Address.lpSockaddr->sa_family == AF_INET6) {
                struct sockaddr_in6* saddr = (struct sockaddr_in6*)unicast->Address.lpSockaddr;
                // Ignore link-local addresses
                if (saddr->sin6_scope_id)
                    continue;
                static const unsigned char localhost[] = {0, 0, 0, 0, 0, 0, 0, 0,
                                                          0, 0, 0, 0, 0, 0, 0, 1};
                static const unsigned char localhost_mapped[] = {0, 0, 0,    0,    0,    0, 0, 0,
                                                                 0, 0, 0xff, 0xff, 0x7f, 0, 0, 1};
                if ((unicast->DadState == NldsPreferred) &&
                    memcmp(saddr->sin6_addr.s6_addr, localhost, 16) &&
                    memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16)) {
                    int log_addr = 0;
                    if (first_ipv6) {
                        service_address_ipv6 = *saddr;
                        first_ipv6 = 0;
                        log_addr = 1;
                    }
                    has_ipv6 = 1;
                    if (num_sockets < max_sockets) {
                        saddr->sin6_port = htons((unsigned short)port);
                        int sock = mdns_socket_open_ipv6(saddr);
                        if (sock >= 0) {
                            sockets[num_sockets++] = sock;
                            log_addr = 1;
                        } else {
                            log_addr = 0;
                        }
                    }
                    if (log_addr) {
                        char buffer[128];
                        mdns_string_t addr = ipv6_address_to_string(buffer, sizeof(buffer), saddr,
                                                                    sizeof(struct sockaddr_in6));
                        printf("Local IPv6 address: %.*s\n", MDNS_STRING_FORMAT(addr));
                    }
                }
            }
        }
    }

    free(adapter_address);

#else

    struct ifaddrs *ifaddr = 0;
    struct ifaddrs *ifa = 0;

    if(getifaddrs(&ifaddr) < 0)
        printf("Unable to get interface addresses\n");

    int first_ipv4 = 1;
    int first_ipv6 = 1;
    for(ifa = ifaddr; ifa; ifa = ifa->ifa_next)
    {
        if(!ifa->ifa_addr)
            continue;
        if(!(ifa->ifa_flags & IFF_UP) || !(ifa->ifa_flags & IFF_MULTICAST))
            continue;
        if((ifa->ifa_flags & IFF_LOOPBACK) || (ifa->ifa_flags & IFF_POINTOPOINT))
            continue;

        if(ifa->ifa_addr->sa_family == AF_INET)
        {
            struct sockaddr_in *saddr = (struct sockaddr_in *) ifa->ifa_addr;
            if(saddr->sin_addr.s_addr != htonl(INADDR_LOOPBACK))
            {
                int log_addr = 0;
                if(first_ipv4)
                {
                    service_address_ipv4 = *saddr;
                    first_ipv4 = 0;
                    log_addr = 1;
                }
                has_ipv4 = 1;
                if(num_sockets < max_sockets)
                {
                    saddr->sin_port = htons(port);
                    int sock = mdns_socket_open_ipv4(saddr);
                    if(sock >= 0)
                    {
                        sockets[num_sockets++] = sock;
                        log_addr = 1;
                    }
                    else
                    {
                        log_addr = 0;
                    }
                }
                if(log_addr)
                {
                    char buffer[128];
                    mdns_string_t addr = ipv4_address_to_string(buffer, sizeof(buffer), saddr,
                                                                sizeof(struct sockaddr_in));
                    printf("Local IPv4 address: %.*s\n", MDNS_STRING_FORMAT(addr));
                }
            }
        }
        else if(ifa->ifa_addr->sa_family == AF_INET6)
        {
            struct sockaddr_in6 *saddr = (struct sockaddr_in6 *) ifa->ifa_addr;
            // Ignore link-local addresses
            if(saddr->sin6_scope_id)
                continue;
            static const unsigned char localhost[] = {
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 1
            };
            static const unsigned char localhost_mapped[] = {
                0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0xff, 0xff, 0x7f, 0, 0, 1
            };
            if(memcmp(saddr->sin6_addr.s6_addr, localhost, 16) &&
               memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16))
            {
                int log_addr = 0;
                if(first_ipv6)
                {
                    service_address_ipv6 = *saddr;
                    first_ipv6 = 0;
                    log_addr = 1;
                }
                has_ipv6 = 1;
                if(num_sockets < max_sockets)
                {
                    saddr->sin6_port = htons(port);
                    int sock = mdns_socket_open_ipv6(saddr);
                    if(sock >= 0)
                    {
                        sockets[num_sockets++] = sock;
                        log_addr = 1;
                    }
                    else
                    {
                        log_addr = 0;
                    }
                }
                if(log_addr)
                {
                    char buffer[128];
                    mdns_string_t addr = ipv6_address_to_string(buffer, sizeof(buffer), saddr,
                                                                sizeof(struct sockaddr_in6));
                    printf("Local IPv6 address: %.*s\n", MDNS_STRING_FORMAT(addr));
                }
            }
        }
    }

    freeifaddrs(ifaddr);

#endif

    return num_sockets;
}

int mdnspp::open_service_sockets(int *sockets, int max_sockets, sockaddr_in &service_address_ipv4, sockaddr_in6 &service_address_ipv6)
{
// When recieving, each socket can recieve data from all network interfaces
// Thus we only need to open one socket for each address family
    int num_sockets = 0;

// Call the client socket function to enumerate and get local addresses,
// but not open the actual sockets
    open_client_sockets(0, 0, 0, service_address_ipv4, service_address_ipv6);

    if(num_sockets < max_sockets)
    {
        struct sockaddr_in sock_addr;
        memset(&sock_addr,
               0, sizeof(struct sockaddr_in));
        sock_addr.
            sin_family = AF_INET;
#ifdef _WIN32
        sock_addr.sin_addr = in4addr_any;
#else
        sock_addr.sin_addr.
            s_addr = INADDR_ANY;
#endif
        sock_addr.
            sin_port = htons(MDNS_PORT);
#ifdef __APPLE__
        sock_addr.sin_len = sizeof(struct sockaddr_in);
#endif
        int sock = mdns_socket_open_ipv4(&sock_addr);
        if(sock >= 0)
            sockets[num_sockets++] =
                sock;
    }

    if(num_sockets < max_sockets)
    {
        struct sockaddr_in6 sock_addr;
        memset(&sock_addr,
               0, sizeof(struct sockaddr_in6));
        sock_addr.
            sin6_family = AF_INET6;
        sock_addr.
            sin6_addr = in6addr_any;
        sock_addr.
            sin6_port = htons(MDNS_PORT);
#ifdef __APPLE__
        sock_addr.sin6_len = sizeof(struct sockaddr_in6);
#endif
        int sock = mdns_socket_open_ipv6(&sock_addr);
        if(sock >= 0)
            sockets[num_sockets++] =
                sock;
    }

    return
        num_sockets;
}

