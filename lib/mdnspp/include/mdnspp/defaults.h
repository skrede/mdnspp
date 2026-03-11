#ifndef HPP_GUARD_MDNSPP_DEFAULTS_H
#define HPP_GUARD_MDNSPP_DEFAULTS_H

// defaults.h — convenience header for DefaultPolicy users.
//
// Provides unqualified type aliases so users can write:
//   mdnspp::observer obs{ctx, cb};          // no angle brackets
//   mdnspp::querier  q{ctx, 500ms};
//   mdnspp::service_discovery sd{ctx, 1s};
//   mdnspp::service_server    srv{ctx, info};
//   mdnspp::context           ctx;
//
// ASIO users should instead include the basic_*.h headers directly and
// instantiate with their own policy, e.g.:
//   mdnspp::basic_observer<mdnspp::AsioPolicy> obs{io, cb};
//
// NOTE: including this header transitively pulls in DefaultPolicy and its
// dependencies (platform headers, system socket headers). If you are writing
// a shared TU that must remain free of platform headers (e.g. an ASIO
// completion token adapter), include basic_*.h directly instead.

#include "mdnspp/basic_querier.h"
#include "mdnspp/basic_observer.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/network_interface.h"
#include "mdnspp/basic_service_server.h"
#include "mdnspp/basic_service_monitor.h"
#include "mdnspp/basic_service_discovery.h"

#include "mdnspp/default/default_policy.h"

namespace mdnspp {

/// Convenience alias — mDNS multicast listener with the default platform policy.
using observer = basic_observer<DefaultPolicy>;

/// Convenience alias — mDNS query client with the default platform policy.
using querier = basic_querier<DefaultPolicy>;

/// Convenience alias — mDNS service browser/discoverer with the default platform policy.
using service_discovery = basic_service_discovery<DefaultPolicy>;

/// Convenience alias — mDNS service responder with the default platform policy.
using service_server = basic_service_server<DefaultPolicy>;

/// Convenience alias — continuous mDNS service monitor with the default platform policy.
using service_monitor = basic_service_monitor<DefaultPolicy>;

/// Convenience alias — the default event-loop context (run(), stop(), restart()).
using context = DefaultContext;

}

#endif
