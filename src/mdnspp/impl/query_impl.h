#ifndef MDNSPP_QUERY_IMPL_H
#define MDNSPP_QUERY_IMPL_H

#include "mdnspp/query.h"

#include "mdnspp/impl/mdns_base.h"

namespace mdnspp {

class query::impl : public mdns_base
{
public:
    void send_query(mdns_query_t *query, size_t count);

private:
    int callback(int sock, const struct sockaddr *from, size_t addrlen, mdns_entry_type_t entry,
                 uint16_t query_id, uint16_t rtype, uint16_t rclass, uint32_t ttl, const void *data,
                 size_t size, size_t name_offset, size_t name_length, size_t record_offset, size_t record_length) override;
};

}

#endif
