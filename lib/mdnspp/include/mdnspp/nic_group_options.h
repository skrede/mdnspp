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
    /// Interval between interface enumeration polls when no native backend is
    /// active (and the floor of change-detection latency in that mode).
    std::chrono::milliseconds poll_interval{std::chrono::seconds(5)};

    /// Optional replacement for enumerate_interfaces(). When set, the
    /// platform-native change-notification backends are bypassed and the
    /// monitor polls this callable every @c poll_interval instead. Intended
    /// for tests and for callers that supply a curated interface universe.
    move_only_function<std::vector<network_interface>(std::error_code &)> enumerator{};
};

struct server_peer_options
{
    service_info info;
    service_options service{};
};

/// Group-level options for basic_nic_group.
///
/// Event callbacks are registered here, at group level, rather than in the
/// per-NIC monitor_options / observer_options elements: basic_nic_group
/// rejects per-NIC monitor and observer options that carry callbacks (see
/// basic_nic_group). Each callback fires once per interface, with the
/// originating network_interface passed as the leading parameter; the group
/// performs no cross-interface deduplication of events.
template <policy_like P>
struct basic_nic_group_options
{
    dedup_mode dedup{dedup_mode::merged};
    move_only_function<bool(const network_interface &)> interface_filter{};
    move_only_function<policy_socket_options_t<P>(const network_interface &)> socket_options_factory{};
    mdns_options mdns_opts{};
    nic_monitor_options monitor_opts{};

    /// Fired once per interface when a service instance becomes fully resolved
    /// on that interface. The leading network_interface identifies the
    /// originating interface; resolved_service::source_interface is not
    /// populated in callback payloads. Requires basic_service_monitor in the
    /// Peers pack.
    move_only_function<void(const network_interface &, const resolved_service &)> on_found{};

    /// Fired once per interface when a record change alters an
    /// already-resolved service on that interface. Requires
    /// basic_service_monitor in the Peers pack.
    move_only_function<void(const network_interface &, const resolved_service &, update_event, dns_type)> on_updated{};

    /// Fired once per interface when a service is no longer reachable on that
    /// interface. Requires basic_service_monitor in the Peers pack.
    move_only_function<void(const network_interface &, const resolved_service &, loss_reason)> on_lost{};

    /// Fired once per interface per parsed record. Requires basic_observer in
    /// the Peers pack.
    move_only_function<void(const network_interface &, const endpoint &, const mdns_record_variant &)> on_record{};

    /// Fired on fire-and-forget send failures and fatal receive errors of any
    /// per-NIC instance, stamped with the originating interface. Per-NIC
    /// server instances use this handler only when the corresponding
    /// server_peer_options::service::on_error is unset.
    move_only_function<void(const network_interface &, std::error_code, std::string_view)> on_error{};
};

namespace detail {

/// Primary template — specialised in detail/peer_traits.h for each supported peer type.
template <template <typename...> class Peer, typename P>
struct peer_traits;

}

}

#endif
