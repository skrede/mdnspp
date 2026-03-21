#ifndef HPP_GUARD_MDNSPP_DETAIL_PEER_TRAITS_H
#define HPP_GUARD_MDNSPP_DETAIL_PEER_TRAITS_H

#include "mdnspp/policy.h"
#include "mdnspp/nic_group_options.h"
#include "mdnspp/observer_options.h"
#include "mdnspp/monitor_options.h"

namespace mdnspp {

template <Policy P> class basic_observer;
template <Policy P, typename Clock> class basic_service_monitor;
template <Policy P> class basic_service_server;

template <typename P>
struct peer_traits<basic_service_monitor, P>
{
    using options_type = monitor_options;
    static constexpr bool provides_services{true};
    static constexpr bool provides_announce{false};
    static constexpr bool provides_observe{false};
};

template <typename P>
struct peer_traits<basic_service_server, P>
{
    using options_type = server_peer_options;
    static constexpr bool provides_services{false};
    static constexpr bool provides_announce{true};
    static constexpr bool provides_observe{false};
};

template <typename P>
struct peer_traits<basic_observer, P>
{
    using options_type = observer_options;
    static constexpr bool provides_services{false};
    static constexpr bool provides_announce{false};
    static constexpr bool provides_observe{true};
};

}

#endif
