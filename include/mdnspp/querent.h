#ifndef HPP_GUARD_MDNSPP_QUERENT_H
#define HPP_GUARD_MDNSPP_QUERENT_H

#include "mdnspp/socket_policy.h"
#include "mdnspp/records.h"
#include "mdnspp/mdns_error.h"

namespace mdnspp {

template <SocketPolicy S>
class querent
{
public:
    explicit querent(S socket)
        : m_socket(std::move(socket))
    {
    }

    // Method stub — implementation in Phase 4
    void query()
    {
        static_assert(detail::always_false<S>::value,
                      "querent<S>::query() not yet implemented — Phase 4");
    }

private:
    S m_socket;
};

}

#endif // HPP_GUARD_MDNSPP_QUERENT_H
