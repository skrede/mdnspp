#ifndef MDNSPP_SERVICE_DISCOVERY_H
#define MDNSPP_SERVICE_DISCOVERY_H

#include "mdnspp/socket_policy.h"
#include "mdnspp/records.h"
#include "mdnspp/mdns_error.h"

namespace mdnspp {

namespace detail {
template<typename T> struct always_false : std::false_type {};
} // namespace detail

template<SocketPolicy S>
class service_discovery
{
public:
    explicit service_discovery(S socket)
        : m_socket(std::move(socket))
    {}

    // Method stub — implementation in Phase 4
    void discover()
    {
        static_assert(detail::always_false<S>::value,
            "service_discovery<S>::discover() not yet implemented — Phase 4");
    }

private:
    S m_socket;
};

} // namespace mdnspp

#endif // MDNSPP_SERVICE_DISCOVERY_H
