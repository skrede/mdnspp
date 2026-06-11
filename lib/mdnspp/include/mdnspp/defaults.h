#ifndef HPP_GUARD_MDNSPP_DEFAULTS_H
#define HPP_GUARD_MDNSPP_DEFAULTS_H

// defaults.h — convenience header for default_policy users.
//
// Provides unqualified type aliases so users can write:
//   mdnspp::context ctx;
//   mdnspp::observer obs{ctx, mdnspp::observer_options{.on_record = cb}};
//   mdnspp::querier  q{ctx, mdnspp::query_options{.silence_timeout = std::chrono::milliseconds(500)}};
//   mdnspp::service_discovery sd{ctx, mdnspp::query_options{.silence_timeout = std::chrono::seconds(1)}};
//   mdnspp::service_server    srv{ctx, info};
//
// ASIO users should instead include the basic_*.h headers directly and
// instantiate with their own policy, e.g.:
//   mdnspp::basic_observer<mdnspp::asio_policy> obs{io, mdnspp::observer_options{.on_record = cb}};
//
// NOTE: including this header transitively pulls in default_policy and its
// dependencies (platform headers, system socket headers). If you are writing
// a shared TU that must remain free of platform headers (e.g. an ASIO
// completion token adapter), include basic_*.h directly instead.

#include "mdnspp/basic_querier.h"
#include "mdnspp/basic_observer.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/basic_nic_group.h"
#include "mdnspp/basic_nic_monitor.h"
#include "mdnspp/network_interface.h"
#include "mdnspp/basic_service_server.h"
#include "mdnspp/basic_service_monitor.h"
#include "mdnspp/basic_service_discovery.h"

#include "mdnspp/default/default_policy.h"

namespace mdnspp {

/// Convenience alias — mDNS multicast listener with the default platform policy.
using observer = basic_observer<default_policy>;

/// Convenience alias — mDNS query client with the default platform policy.
using querier = basic_querier<default_policy>;

/// Convenience alias — mDNS service browser/discoverer with the default platform policy.
using service_discovery = basic_service_discovery<default_policy>;

/// Convenience alias — mDNS service responder with the default platform policy.
using service_server = basic_service_server<default_policy>;

/// Convenience alias — continuous mDNS service monitor with the default platform policy.
using service_monitor = basic_service_monitor<default_policy>;

/// Convenience alias — NIC change detector with the default platform policy.
using nic_monitor = basic_nic_monitor<default_policy>;

/// Convenience alias — multi-NIC peer group with the default platform policy.
///
/// Usage: mdnspp::nic_group<basic_service_monitor> grp{ctx, grp_opts, std::vector<mdnspp::monitor_options>{...}};
template <template <typename...> class... Peers>
using nic_group = basic_nic_group<default_policy, Peers...>;

/// Convenience alias — dynamic (runtime-configured) multi-NIC group with the default platform policy.
using dynamic_nic_group = basic_dynamic_nic_group<default_policy>;

/// Convenience alias — NIC group options with the default platform policy.
using nic_group_options = basic_nic_group_options<default_policy>;

/// Convenience alias — the default event-loop context (run(), stop(), restart()).
using context = default_context;

}

#endif
