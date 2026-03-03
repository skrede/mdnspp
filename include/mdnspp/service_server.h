#ifndef HPP_GUARD_MDNSPP_SERVICE_SERVER_H
#define HPP_GUARD_MDNSPP_SERVICE_SERVER_H

#include "mdnspp/socket_policy.h"
#include "mdnspp/records.h"
#include "mdnspp/mdns_error.h"

namespace mdnspp {

template <SocketPolicy S>
class service_server
{
public:
    explicit service_server(S socket)
        : m_socket(std::move(socket))
    {
    }

    // Method stub — implementation in Phase 5
    void announce()
    {
        static_assert(detail::always_false<S>::value,
                      "service_server<S>::announce() not yet implemented — Phase 5");
    }

private:
    S m_socket;
};

}

#endif // HPP_GUARD_MDNSPP_SERVICE_SERVER_H
