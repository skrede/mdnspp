#ifndef HPP_GUARD_MDNSPP_ENCRYPT_DEFAULTS_H
#define HPP_GUARD_MDNSPP_ENCRYPT_DEFAULTS_H

#include "mdnspp/defaults.h"

#include "mdnspp/encrypt/encrypted_policy.h"

namespace mdnspp::encrypt {

using encrypted_observer          = basic_observer<encrypted_policy<default_policy>>;
using encrypted_querier           = basic_querier<encrypted_policy<default_policy>>;
using encrypted_service_discovery = basic_service_discovery<encrypted_policy<default_policy>>;
using encrypted_service_server    = basic_service_server<encrypted_policy<default_policy>>;
using encrypted_service_monitor   = basic_service_monitor<encrypted_policy<default_policy>>;
using encrypted_nic_monitor       = basic_nic_monitor<encrypted_policy<default_policy>>;
using encrypted_nic_group_options = basic_nic_group_options<encrypted_policy<default_policy>>;
using encrypted_dynamic_nic_group = basic_dynamic_nic_group<encrypted_policy<default_policy>>;

template <template <typename...> class... Peers>
using encrypted_nic_group = basic_nic_group<encrypted_policy<default_policy>, Peers...>;

}

#endif
