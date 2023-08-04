#ifndef MDNSPP_DISCOVERYPRIVATE_H
#define MDNSPP_DISCOVERYPRIVATE_H

#include "mdnspp/impl/mdnsbase.h"

namespace mdnspp {

int discovery_callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry,
                       uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data,
                       size_t size, size_t name_offset, size_t name_length, size_t record_offset,
                       size_t record_length, void *user_data);

class DiscoveryPrivate : public MDNSBase
{
public:
    int send_dns_sd();

    void stop();
};

}

#endif
