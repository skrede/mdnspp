#ifndef MDNSPP_MDNS_BASE_H
#define MDNSPP_MDNS_BASE_H

#include "mdnspp/mdns_util.h"

#include <signal.h>

#include <array>
#include <vector>

namespace mdnspp {

int mdnsbase_callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry,
                      uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data,
                      size_t size, size_t name_offset, size_t name_length, size_t record_offset,
                      size_t record_length, void *user_data);

typedef int socket_t;

class mdns_base
{
public:
    mdns_base();
    ~mdns_base();

    uint32_t socket_count() const;

    const sockaddr_in &address_ipv4() const;
    const sockaddr_in6 &address_ipv6() const;

    virtual int callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry, uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data, size_t size, size_t name_offset, size_t name_length, size_t record_offset, size_t record_length) = 0;

protected:
    const std::vector<socket_t> &sockets() const;

    void open_client_sockets(uint16_t port);
    void open_service_sockets();
    void close_sockets();

    std::array<char, 2048> m_buffer;

private:
    uint32_t m_socket_count;
    std::vector<socket_t> m_sockets;

    sockaddr_in m_address_ipv4;
    sockaddr_in6 m_address_ipv6;
};

}

#endif
