#ifndef HPP_GUARD_MDNSPP_DETAIL_PEER_TRAITS_H
#define HPP_GUARD_MDNSPP_DETAIL_PEER_TRAITS_H

#include "mdnspp/policy.h"
#include "mdnspp/nic_group_options.h"
#include "mdnspp/observer_options.h"
#include "mdnspp/monitor_options.h"

#include <system_error>

namespace mdnspp {

template <policy_like P> class basic_observer;
template <policy_like P, typename Clock> class basic_service_monitor;
template <policy_like P> class basic_service_server;

namespace detail {

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

// Per-NIC monitor and observer options passed to basic_nic_group must not
// carry callbacks: the group wires its own interface-stamped forwarding
// lambdas into every per-NIC instance, and a user callback in the per-NIC
// options would be silently displaced by them. Callback-bearing options are
// therefore rejected at configure time with std::errc::invalid_argument.
// Group-level callbacks live in basic_nic_group_options.

inline std::error_code validate_nic_group_peer_options(const monitor_options &opts) noexcept
{
    if(opts.on_found || opts.on_updated || opts.on_lost || opts.on_error)
        return std::make_error_code(std::errc::invalid_argument);
    return {};
}

inline std::error_code validate_nic_group_peer_options(const observer_options &opts) noexcept
{
    if(opts.on_record || opts.on_error)
        return std::make_error_code(std::errc::invalid_argument);
    return {};
}

// Server callbacks are forwarded (shared across per-NIC instances), never rejected.
inline std::error_code validate_nic_group_peer_options(const server_peer_options &) noexcept
{
    return {};
}

}

}

#endif
