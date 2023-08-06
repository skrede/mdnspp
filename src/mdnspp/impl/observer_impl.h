#ifndef MDNSPP_OBSERVER_IMPL_H
#define MDNSPP_OBSERVER_IMPL_H

// Dump all incoming mDNS queries and answers

#include "mdnspp/observer.h"

#include "mdnspp/impl/mdns_base.h"

#include <atomic>

namespace mdnspp {

class observer::impl : public mdns_base
{
public:
    impl();

    void observe();

    void stop();

private:
    std::atomic<bool> m_running;

    void callback(socket_t socket, std::shared_ptr<message_buffer> buffer) override;
};

}

#endif
