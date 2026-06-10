#ifndef HPP_GUARD_MDNSPP_OBSERVER_OPTIONS_H
#define HPP_GUARD_MDNSPP_OBSERVER_OPTIONS_H

#include "mdnspp/callback_types.h"

namespace mdnspp {

struct observer_options
{
    using record_callback = mdnspp::record_callback;
    using error_handler = mdnspp::error_handler;

    /// Callback invoked per parsed record with the sender endpoint.
    record_callback on_record{};

    /// Optional handler invoked on fatal receive errors.
    error_handler on_error{};
};

}

#endif
