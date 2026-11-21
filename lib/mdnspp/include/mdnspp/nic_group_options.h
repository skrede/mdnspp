#ifndef HPP_GUARD_MDNSPP_NIC_GROUP_OPTIONS_H
#define HPP_GUARD_MDNSPP_NIC_GROUP_OPTIONS_H

#include "mdnspp/policy.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/service_info.h"
#include "mdnspp/callback_types.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/monitor_options.h"
#include "mdnspp/service_options.h"
#include "mdnspp/resolved_service.h"
#include "mdnspp/network_interface.h"

#include "mdnspp/detail/compat.h"

#include <chrono>
#include <vector>
#include <string_view>
#include <system_error>

namespace mdnspp {

enum class dedup_mode
{
    merged,
    per_interface,
};

struct nic_monitor_options
{
    std::chrono::milliseconds poll_interval{std::chrono::seconds(5)};
    move_only_function<std::vector<network_interface>(std::error_code &)> enumerator{};
};

struct server_peer_options
{
    service_info info;
    service_options service{};
};

template <policy_like P>
struct basic_nic_group_options
{
    dedup_mode dedup{dedup_mode::merged};
    move_only_function<bool(const network_interface &)> interface_filter{};
    move_only_function<policy_socket_options_t<P>(const network_interface &)> socket_options_factory{};
    mdns_options mdns_opts{};
    nic_monitor_options monitor_opts{};
    move_only_function<void(const network_interface &, const resolved_service &)> on_found{};
    move_only_function<void(const network_interface &, const resolved_service &, update_event, dns_type)> on_updated{};
    move_only_function<void(const network_interface &, const resolved_service &, loss_reason)> on_lost{};
    move_only_function<void(const network_interface &, const endpoint &, const mdns_record_variant &)> on_record{};
    move_only_function<void(const network_interface &, std::error_code, std::string_view)> on_error{};
};

namespace detail {

template <template <typename...> class Peer, typename P>
struct peer_traits;

}

}

#endif
