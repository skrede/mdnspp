#ifndef MDNSPP_DISCOVERY_IMPL_H
#define MDNSPP_DISCOVERY_IMPL_H

#include "mdnspp/discovery.h"

#include "mdnspp/impl/mdns_base.h"

namespace mdnspp {

class discovery::impl : public mdns_base
{
public:
    void discover();
    void stop();

private:
    void callback(socket_t socket, std::shared_ptr<message_buffer> buffer) override;
};

}

#endif
