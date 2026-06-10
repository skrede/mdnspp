#ifndef HPP_GUARD_MDNSPP_NIC_GROUP_OPTIONS_H
#define HPP_GUARD_MDNSPP_NIC_GROUP_OPTIONS_H

#include "mdnspp/policy.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/service_info.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/service_options.h"
#include "mdnspp/network_interface.h"

#include "mdnspp/detail/compat.h"

#include <chrono>

namespace mdnspp {

enum class dedup_mode
{
    merged,
    per_interface,
};

struct nic_monitor_options
{
    std::chrono::milliseconds poll_interval{std::chrono::seconds(5)};
};

struct server_peer_options
{
    service_info info;
    service_options opts{};
};

template <Policy P>
struct basic_nic_group_options
{
    dedup_mode dedup{dedup_mode::merged};
    move_only_function<bool(const network_interface &)> interface_filter{};
    move_only_function<policy_socket_options_t<P>(const network_interface &)> socket_options_factory{};
    mdns_options mdns_opts{};
    nic_monitor_options monitor_opts{};
};

/// Primary template — specialised in detail/peer_traits.h for each supported peer type.
template <template <typename...> class Peer, typename P>
struct peer_traits;

}

#endif
