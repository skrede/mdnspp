#include "mdnspp/mdns_base.h"
#include "mdnspp/message_parser.h"

using namespace mdnspp;

mdns_base::mdns_base(size_t buffer_capacity)
    : m_socket_count(0)
    , m_buffer_capacity(buffer_capacity)
    , m_sink(std::make_shared<log_sink_s<std::cout>>())
{
#ifdef _WIN32
    WORD versionWanted = MAKEWORD(1, 1);
    WSADATA wsaData;
    if (WSAStartup(versionWanted, &wsaData)) {
        error() << "Failed to initialize WinSock";
    }
#endif
}

mdns_base::mdns_base(std::shared_ptr<log_sink> sink, size_t buffer_capacity)
    : m_socket_count(0)
    , m_buffer_capacity(buffer_capacity)
    , m_sink(std::move(sink))
{
#ifdef _WIN32
    WORD versionWanted = MAKEWORD(1, 1);
    WSADATA wsaData;
    if (WSAStartup(versionWanted, &wsaData)) {
        error() << "Failed to initialize WinSock";
    }
#endif
}

mdns_base::~mdns_base()
{
#ifdef _WIN32
    WSACleanup();
#endif
}

void mdns_base::stop()
{
    m_stop = true;
}

size_t mdns_base::socket_count() const
{
    return m_socket_count;
}

bool mdns_base::has_address_ipv4() const
{
    return m_address_ipv4.has_value() && m_address_ipv4->sin_family == AF_INET;
}

bool mdns_base::has_address_ipv6() const
{
    return m_address_ipv6.has_value() && m_address_ipv6->sin6_family == AF_INET6;
}

const std::optional<sockaddr_in> &mdns_base::address_ipv4() const
{
    return m_address_ipv4;
}

const std::optional<sockaddr_in6> &mdns_base::address_ipv6() const
{
    return m_address_ipv6;
}

void mdns_base::open_client_sockets(uint16_t port)
{
    sockaddr_in address_ipv4;
    sockaddr_in6 address_ipv6;
    m_socket_count = open_client_sockets(m_sockets, sizeof(m_sockets) / sizeof(m_sockets[0]), port, address_ipv4, address_ipv6);
    if(m_socket_count <= 0)
        throw std::runtime_error("Failed to open any client sockets");
    if(address_ipv4.sin_family == AF_INET)
        m_address_ipv4.emplace(address_ipv4);
    if(address_ipv6.sin6_family == AF_INET6)
        m_address_ipv6.emplace(address_ipv6);
    debug() << "Opened " << m_socket_count << " client socket" << (m_socket_count == 1 ? "" : "s");
}

void mdns_base::open_service_sockets()
{
    sockaddr_in address_ipv4;
    sockaddr_in6 address_ipv6;
    m_socket_count = open_service_sockets(m_sockets, sizeof(m_sockets) / sizeof(m_sockets[0]), address_ipv4, address_ipv6);
    if(m_socket_count <= 0)
        throw std::runtime_error("Failed to open any service sockets");
    if(address_ipv4.sin_family == AF_INET)
        m_address_ipv4.emplace(address_ipv4);
    if(address_ipv6.sin6_family == AF_INET6)
        m_address_ipv6.emplace(address_ipv6);
    debug() << "Opened " << m_socket_count << " service socket" << (m_socket_count == 1 ? "" : "s") << " for mDNS traffic observation";
}

void mdns_base::close_sockets()
{
    for(int socket = 0; socket < m_socket_count; ++socket)
        mdns_socket_close(m_sockets[socket]);
    debug() << "Closed " << m_socket_count << " socket" << (m_socket_count == 1 ? "" : "s");
}

void mdns_base::send(const std::function<void(index_t, socket_t, void *, size_t)> &send_cb)
{
    char buffer[2048];
    size_t capacity = 2048;
    for(index_t soc_idx = 0; soc_idx < m_socket_count; ++soc_idx)
        send_cb(soc_idx, m_sockets[soc_idx], buffer, capacity);
}

void mdns_base::listen_until_silence(const std::function<size_t(index_t, socket_t, void *, size_t, mdns_record_callback_fn, void *)> &listen_func, std::chrono::milliseconds timeout)
{
    auto buffer = std::make_unique<char[]>(m_buffer_capacity);

    size_t records = 0u;
    int ready_descriptors;
    m_stop = false;

    auto sec = std::chrono::duration_cast<std::chrono::seconds>(timeout);
    auto usec = std::chrono::duration_cast<std::chrono::microseconds>(timeout) - std::chrono::duration_cast<std::chrono::microseconds>(sec);
    do
    {
        timeval time_out{
#ifdef WIN32
            static_cast<long>(sec.count()),
            static_cast<long>(usec.count())
#elif defined __APPLE__
            sec.count(),
            static_cast<int>(usec.count())
#else
            sec.count(),
            usec.count()
#endif
        };

        int nfds = 0;
        fd_set readfs;
        FD_ZERO(&readfs);
        for(index_t soc_idx = 0; soc_idx < m_socket_count; ++soc_idx)
        {
            if(m_sockets[soc_idx] >= nfds)
                nfds = m_sockets[soc_idx] + 1;
            FD_SET(m_sockets[soc_idx], &readfs);
        }

        records = 0u;
        ready_descriptors = select(nfds, &readfs, nullptr, nullptr, &time_out);
        if(ready_descriptors > 0)
            for(index_t soc_idx = 0; soc_idx < m_socket_count; ++soc_idx)
                if(FD_ISSET(m_sockets[soc_idx], &readfs))
                    records += listen_func(soc_idx, m_sockets[soc_idx], buffer.get(), m_buffer_capacity, mdns_base::mdns_callback, this);
    } while(ready_descriptors > 0 && !m_stop);
}

int mdns_base::mdns_callback(socket_t socket, const sockaddr *from, size_t addrlen, mdns_entry_type_t entry, uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl,
                             const void *data, size_t size, size_t name_offset, size_t name_length, size_t record_offset, size_t record_length, void *user_data)
{
    message_buffer buffer(from, addrlen, entry, query_id, static_cast<mdns_record_type>(rtype), rclass, ttl, data, size, name_offset, name_length, record_offset, record_length);
    static_cast<mdns_base *>(user_data)->callback(socket, buffer);
    return 0;
}

logger<log_level::trace> mdns_base::trace()
{
    return {m_sink};
}

logger<log_level::debug> mdns_base::debug()
{
    return {m_sink};
}

logger<log_level::info> mdns_base::info()
{
    return {m_sink};
}

logger<log_level::warn> mdns_base::warn()
{
    return {m_sink};
}

logger<log_level::err> mdns_base::error()
{
    return {m_sink};
}

logger<log_level::trace> mdns_base::trace(const std::string &label)
{
    return {label, m_sink};
}

logger<log_level::debug> mdns_base::debug(const std::string &label)
{
    return {label, m_sink};
}

logger<log_level::info> mdns_base::info(const std::string &label)
{
    return {label, m_sink};
}

logger<log_level::warn> mdns_base::warn(const std::string &label)
{
    return {label, m_sink};
}

logger<log_level::err> mdns_base::error(const std::string &label)
{
    return {label, m_sink};
}

int mdns_base::open_client_sockets(int *sockets, int max_sockets, int port, sockaddr_in &service_address_ipv4, sockaddr_in6 &service_address_ipv6)
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
                auto saddr = reinterpret_cast<sockaddr_in*>(unicast->Address.lpSockaddr);
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
                        mdns_string_t addr = ipv4_address_to_string(buffer, sizeof(buffer), saddr, sizeof(sockaddr_in));
                       debug() << std::format("Local IPv4 address: {}", std::string(addr.str, addr.length));
                    }
                }
            } else if (unicast->Address.lpSockaddr->sa_family == AF_INET6) {
                auto saddr = reinterpret_cast<sockaddr_in6*>(unicast->Address.lpSockaddr);
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
                        mdns_string_t addr = ipv6_address_to_string(buffer, sizeof(buffer), saddr, sizeof(sockaddr_in6));
                        debug() << std::format("Local IPv6 address: {}", std::string(addr.str, addr.length));
                    }
                }
            }
        }
    }

    free(adapter_address);

#else

    ifaddrs *ifaddr = 0;
    ifaddrs *ifa = 0;

    if(getifaddrs(&ifaddr) < 0)
        error() << "Unable to get interface addresses";

    bool first_ipv4 = true;
    bool first_ipv6 = true;
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
            auto saddr = reinterpret_cast<sockaddr_in *>(ifa->ifa_addr);
            if(saddr->sin_addr.s_addr != htonl(INADDR_LOOPBACK))
            {
                int log_addr = 0;
                if(first_ipv4)
                {
                    service_address_ipv4 = *saddr;
                    first_ipv4 = false;
                    log_addr = 1;
                }
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
                    mdns_string_t addr = ipv4_address_to_string(buffer, sizeof(buffer), saddr, sizeof(sockaddr_in));
                    debug() << std::format("Local IPv4 address: {}", std::string(addr.str, addr.length));
                }
            }
        }
        else if(ifa->ifa_addr->sa_family == AF_INET6)
        {
            auto saddr = reinterpret_cast<sockaddr_in6 *>(ifa->ifa_addr);
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
            if(memcmp(saddr->sin6_addr.s6_addr, localhost, 16) && memcmp(saddr->sin6_addr.s6_addr, localhost_mapped, 16))
            {
                int log_addr = 0;
                if(first_ipv6)
                {
                    service_address_ipv6 = *saddr;
                    first_ipv6 = false;
                    log_addr = 1;
                }
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
                    mdns_string_t addr = ipv6_address_to_string(buffer, sizeof(buffer), saddr, sizeof(sockaddr_in6));
                    debug() << std::format("Local IPv6 address: {}", std::string(addr.str, addr.length));
                }
            }
        }
    }

    freeifaddrs(ifaddr);

#endif

    return num_sockets;
}

int mdns_base::open_service_sockets(int *sockets, int max_sockets, sockaddr_in &service_address_ipv4, sockaddr_in6 &service_address_ipv6)
{
// When recieving, each socket can recieve data from all network interfaces
// Thus we only need to open one socket for each address family
    int num_sockets = 0;

// Call the client socket function to enumerate and get local addresses,
// but not open the actual sockets
    open_client_sockets(nullptr, 0, 0, service_address_ipv4, service_address_ipv6);

    if(num_sockets < max_sockets)
    {
        sockaddr_in sock_addr;
        memset(&sock_addr, 0, sizeof(sockaddr_in));
        sock_addr.sin_family = AF_INET;
#ifdef _WIN32
#ifdef __MINGW32__
        sock_addr.sin_addr.s_addr = INADDR_ANY;
#else
        sock_addr.sin_addr = in4addr_any;
#endif
#else
        sock_addr.sin_addr.s_addr = INADDR_ANY;
#endif
        sock_addr.sin_port = htons(MDNS_PORT);
#ifdef __APPLE__
        sock_addr.sin_len = sizeof(sockaddr_in);
#endif
        int sock = mdns_socket_open_ipv4(&sock_addr);
        if(sock >= 0)
            sockets[num_sockets++] = sock;
    }

    if(num_sockets < max_sockets)
    {
        sockaddr_in6 sock_addr;
        memset(&sock_addr, 0, sizeof(sockaddr_in6));
        sock_addr.sin6_family = AF_INET6;
        sock_addr.sin6_addr = in6addr_any;
        sock_addr.sin6_port = htons(MDNS_PORT);
#ifdef __APPLE__
        sock_addr.sin6_len = sizeof(sockaddr_in6);
#endif
        int sock = mdns_socket_open_ipv6(&sock_addr);
        if(sock >= 0)
            sockets[num_sockets++] = sock;
    }

    return num_sockets;
}
