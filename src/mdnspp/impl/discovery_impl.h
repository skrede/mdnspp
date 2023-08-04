#ifndef MDNSPP_DISCOVERY_IMPL_H
#define MDNSPP_DISCOVERY_IMPL_H

#include "mdnspp/discovery.h"

#include "mdnspp/impl/mdnsbase.h"

namespace mdnspp {

class Discovery::Impl : public MDNSBase
{
public:
    int send_dns_sd();
    void stop();

    int callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry, uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data, size_t size, size_t name_offset, size_t name_length, size_t record_offset, size_t record_length) override;
};

}

#endif
