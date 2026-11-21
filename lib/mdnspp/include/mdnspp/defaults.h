#ifndef HPP_GUARD_MDNSPP_DEFAULTS_H
#define HPP_GUARD_MDNSPP_DEFAULTS_H

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

using observer = basic_observer<default_policy>;
using querier = basic_querier<default_policy>;
using service_discovery = basic_service_discovery<default_policy>;
using service_server = basic_service_server<default_policy>;
using service_monitor = basic_service_monitor<default_policy>;
using nic_monitor = basic_nic_monitor<default_policy>;

template <template <typename...> class... Peers>
using nic_group = basic_nic_group<default_policy, Peers...>;

using dynamic_nic_group = basic_dynamic_nic_group<default_policy>;
using nic_group_options = basic_nic_group_options<default_policy>;
using context = default_context;

}

#endif
