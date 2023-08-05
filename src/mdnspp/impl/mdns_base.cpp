#include "mdnspp/impl/mdns_base.h"

using namespace mdnspp;

#ifdef _WIN32
BOOL console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT) {
        running = 0;
    }
    return TRUE;
}
#else
void signal_handler(int signal)
{
    printf("Signal received, %s", signal);
//    running = 0;
}
#endif

// Callback handling parsing answers to queries sent
int mdnspp::mdnsbase_callback(socket_t socket, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry,
                              uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data,
                              size_t size, size_t name_offset, size_t name_length, size_t record_offset,
                              size_t record_length, void *user_data)
{
    return static_cast<mdns_base *>(user_data)->callback(socket, from, addrlen, entry, query_id, rtype, rclass, ttl, data, size, name_offset, name_length, record_offset, record_length);
}

mdns_base::mdns_base()
    : m_socket_count(0)
{
    const char *hostname = "dummy-host";

#ifdef _WIN32
    WORD versionWanted = MAKEWORD(1, 1);
    WSADATA wsaData;
    if (WSAStartup(versionWanted, &wsaData)) {
        exception() << "Failed to initialize WinSock";
    }

    char hostname_buffer[256];
    DWORD hostname_size = (DWORD)sizeof(hostname_buffer);
    if(GetComputerNameA(hostname_buffer, &hostname_size))
        hostname = hostname_buffer;

    SetConsoleCtrlHandler(console_handler, TRUE);
#else
    char hostname_buffer[256];
    size_t hostname_size = sizeof(hostname_buffer);
    if(gethostname(hostname_buffer, hostname_size) == 0)
        hostname = hostname_buffer;
    signal(SIGINT, signal_handler);
#endif
}

mdns_base::~mdns_base()
{
#ifdef _WIN32
    WSACleanup();
#endif
}

size_t mdns_base::socket_count()
{
    return m_socket_count;
}

bool mdns_base::has_address_ipv4()
{
    return m_address_ipv4.sin_family == AF_INET;
}

bool mdns_base::has_address_ipv6()
{
    return m_address_ipv6.sin6_family == AF_INET6;
}

const sockaddr_in &mdns_base::address_ipv4()
{
    return m_address_ipv4;
}

const sockaddr_in6 &mdns_base::address_ipv6()
{
    return m_address_ipv6;
}

void mdns_base::open_client_sockets(uint16_t port)
{
    m_socket_count = mdnspp::open_client_sockets(m_sockets, sizeof(m_sockets) / sizeof(m_sockets[0]), port, m_address_ipv4, m_address_ipv6);
    if(m_socket_count <= 0)
        mdnspp::exception() << "Failed to open any client sockets";
    mdnspp::debug() << "Opened " << m_socket_count << " client socket" << (m_socket_count == 1 ? "" : "s") << " for DNS-SD";
}

void mdns_base::open_service_sockets()
{
    m_socket_count = mdnspp::open_service_sockets(m_sockets, sizeof(m_sockets) / sizeof(m_sockets[0]), m_address_ipv4, m_address_ipv6);
    if(m_socket_count <= 0)
        mdnspp::exception() << "Failed to open any service sockets";
    mdnspp::debug() << "Opened " << m_socket_count << " service socket" << (m_socket_count == 1 ? "" : "s") << " for mDNS traffic observation";
}

void mdns_base::close_sockets()
{
    for(int socket = 0; socket < m_socket_count; ++socket)
        mdns_socket_close(m_sockets[socket]);
    mdnspp::debug() << "Closed " << m_socket_count << " socket" << (m_socket_count == 1 ? "" : "s");
}