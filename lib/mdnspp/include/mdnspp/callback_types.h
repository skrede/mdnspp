#ifndef HPP_GUARD_MDNSPP_CALLBACK_TYPES_H
#define HPP_GUARD_MDNSPP_CALLBACK_TYPES_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/detail/compat.h"

#include <string_view>
#include <system_error>
#include <vector>

namespace mdnspp {

/// Callback invoked per record as results arrive during a query or observation.
using record_callback = detail::move_only_function<void(const endpoint &, const mdns_record_variant &)>;

/// Error handler invoked on fire-and-forget send failures.
using error_handler = detail::move_only_function<void(std::error_code, std::string_view)>;

/// Completion handler for basic_querier.
/// Receives error_code and the accumulated results on completion.
using querier_completion_handler = detail::move_only_function<void(std::error_code, std::vector<mdns_record_variant>)>;

/// Completion handler for basic_observer.
/// Receives error_code when stop() is called.
using observer_completion_handler = detail::move_only_function<void(std::error_code)>;

/// Completion handler for basic_service_discovery.
/// Receives error_code and a const reference to the accumulated results.
using discovery_completion_handler = detail::move_only_function<void(std::error_code, const std::vector<mdns_record_variant> &)>;

/// Completion handler for basic_service_server.
/// Receives error_code when stop() is called or on probe lifecycle events.
using server_completion_handler = detail::move_only_function<void(std::error_code)>;

/// Completion handler for basic_service_monitor.
/// Receives error_code when stop() is called.
using monitor_completion_handler = detail::move_only_function<void(std::error_code)>;

}

#endif
