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
int mdnspp::mdnsbase_callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry,
                              uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data,
                              size_t size, size_t name_offset, size_t name_length, size_t record_offset,
                              size_t record_length, void *user_data)
{
    return static_cast<mdns_base *>(user_data)->callback(sock, from, addrlen, entry, query_id, rtype, rclass, ttl, data, size, name_offset, name_length, record_offset, record_length);
}

mdns_base::mdns_base()
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
void mdns_base::open_client_sockets(uint16_t port)
{
    num_sockets = mdnspp::open_client_sockets(sockets, sizeof(sockets) / sizeof(sockets[0]), port, service_address_ipv4, service_address_ipv6);
    if(num_sockets <= 0)
        mdnspp::exception() << "Failed to open any client sockets";
    mdnspp::debug() << "Opened " << num_sockets << " client socket" << (num_sockets == 1 ? "" : "s") << " for DNS-SD";
}

void mdns_base::open_service_sockets()
{
    num_sockets = mdnspp::open_service_sockets(sockets, sizeof(sockets) / sizeof(sockets[0]), service_address_ipv4, service_address_ipv6);
    if(num_sockets <= 0)
        mdnspp::exception() << "Failed to open any service sockets";
    mdnspp::debug() << "Opened " << num_sockets << " service socket" << (num_sockets == 1 ? "" : "s") << " for mDNS traffic observation";
}

void mdns_base::close_sockets()
{
    for(int socket = 0; socket < num_sockets; ++socket)
        mdns_socket_close(sockets[socket]);
    mdnspp::debug() << "Closed " << num_sockets << " socket" << (num_sockets == 1 ? "" : "s");
}
