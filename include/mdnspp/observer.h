#ifndef HPP_GUARD_MDNSPP_OBSERVER_H
#define HPP_GUARD_MDNSPP_OBSERVER_H

#include "mdnspp/socket_policy.h"
#include "mdnspp/records.h"
#include "mdnspp/mdns_error.h"

namespace mdnspp {

template <SocketPolicy S>
class observer
{
public:
    explicit observer(S socket)
        : m_socket(std::move(socket))
    {
    }

    // Method stubs — implementation in Phase 6
    void observe()
    {
        static_assert(detail::always_false<S>::value,
                      "observer<S>::observe() not yet implemented — Phase 6");
    }

    void stop()
    {
        static_assert(detail::always_false<S>::value,
                      "observer<S>::stop() not yet implemented — Phase 6");
    }

private:
    S m_socket;
};

}

#endif // HPP_GUARD_MDNSPP_OBSERVER_H
