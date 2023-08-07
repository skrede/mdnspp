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
    void callback(socket_t socket, message_buffer &buffer) override;
};

}

#endif
