#ifndef MDNSPP_MDNS_BASE_H
#define MDNSPP_MDNS_BASE_H

#include "mdnspp/mdns_util.h"

#include <signal.h>

namespace mdnspp {

int mdnsbase_callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry,
             uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data,
             size_t size, size_t name_offset, size_t name_length, size_t record_offset,
             size_t record_length, void *user_data);

class mdns_base
{
public:
    mdns_base();
    ~mdns_base();

    virtual int callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry, uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data, size_t size, size_t name_offset, size_t name_length, size_t record_offset, size_t record_length) = 0;

protected:
    int sockets[32];
    int num_sockets;
    size_t capacity = 2048;

    sockaddr_in service_address_ipv4;
    sockaddr_in6 service_address_ipv6;
};

}

#endif
