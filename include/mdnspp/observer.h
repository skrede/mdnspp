#ifndef MDNSPP_OBSERVER_H
#define MDNSPP_OBSERVER_H

#include "mdnspp/socket_policy.h"
#include "mdnspp/records.h"
#include "mdnspp/mdns_error.h"

namespace mdnspp {

namespace detail {
template<typename T> struct always_false : std::false_type {};
} // namespace detail

template<SocketPolicy S>
class observer
{
public:
    explicit observer(S socket)
        : m_socket(std::move(socket))
    {}

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

} // namespace mdnspp

#endif // MDNSPP_OBSERVER_H
