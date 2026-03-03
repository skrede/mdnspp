#ifndef HPP_GUARD_MDNSPP_SERVICE_DISCOVERY_H
#define HPP_GUARD_MDNSPP_SERVICE_DISCOVERY_H

#include "mdnspp/socket_policy.h"
#include "mdnspp/records.h"
#include "mdnspp/mdns_error.h"

namespace mdnspp {

template <SocketPolicy S>
class service_discovery
{
public:
    explicit service_discovery(S socket)
        : m_socket(std::move(socket))
    {
    }

    // Method stub — implementation in Phase 4
    void discover()
    {
        static_assert(detail::always_false<S>::value,
                      "service_discovery<S>::discover() not yet implemented — Phase 4");
    }

private:
    S m_socket;
};

}

#endif // HPP_GUARD_MDNSPP_SERVICE_DISCOVERY_H
