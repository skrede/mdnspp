#ifndef HPP_GUARD_MDNSPP_QUERY_OPTIONS_H
#define HPP_GUARD_MDNSPP_QUERY_OPTIONS_H

#include "mdnspp/callback_types.h"

#include <chrono>

namespace mdnspp {

struct query_options
{
    using record_callback = mdnspp::record_callback;
    using error_handler = mdnspp::error_handler;

    /// Optional callback invoked per relevant record as results arrive.
    record_callback on_record{};

    /// Optional handler invoked on fire-and-forget send failures and fatal
    /// receive errors.
    error_handler on_error{};

    /// Duration of network silence after which the operation completes
    /// successfully. Must be positive.
    std::chrono::milliseconds silence_timeout{3000};
};

}

#endif
