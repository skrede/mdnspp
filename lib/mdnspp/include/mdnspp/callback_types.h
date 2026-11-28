#ifndef HPP_GUARD_MDNSPP_CALLBACK_TYPES_H
#define HPP_GUARD_MDNSPP_CALLBACK_TYPES_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/resolved_service.h"

#include "mdnspp/detail/compat.h"

#include <vector>
#include <string_view>
#include <system_error>

namespace mdnspp {

using record_callback = move_only_function<void(const endpoint &, const mdns_record_variant &)>;
using error_handler = move_only_function<void(std::error_code, std::string_view)>;
using querier_completion_handler = move_only_function<void(std::error_code, std::vector<mdns_record_variant>)>;
using observer_completion_handler = move_only_function<void(std::error_code)>;
using discovery_completion_handler = move_only_function<void(std::error_code, std::vector<mdns_record_variant>)>;
using browse_completion_handler = move_only_function<void(std::error_code, std::vector<resolved_service>)>;
using server_completion_handler = move_only_function<void(std::error_code)>;
using monitor_completion_handler = move_only_function<void(std::error_code)>;

}

#endif
