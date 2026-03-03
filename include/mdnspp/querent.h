#ifndef MDNSPP_QUERENT_H
#define MDNSPP_QUERENT_H

#include "mdnspp/socket_policy.h"
#include "mdnspp/records.h"
#include "mdnspp/mdns_error.h"

namespace mdnspp {

namespace detail {
template<typename T> struct always_false : std::false_type {};
} // namespace detail

template<SocketPolicy S>
class querent
{
public:
    explicit querent(S socket)
        : m_socket(std::move(socket))
    {}

    // Method stub — implementation in Phase 4
    void query()
    {
        static_assert(detail::always_false<S>::value,
            "querent<S>::query() not yet implemented — Phase 4");
    }

private:
    S m_socket;
};

} // namespace mdnspp

#endif // MDNSPP_QUERENT_H
