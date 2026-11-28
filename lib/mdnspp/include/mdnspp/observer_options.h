#ifndef HPP_GUARD_MDNSPP_OBSERVER_OPTIONS_H
#define HPP_GUARD_MDNSPP_OBSERVER_OPTIONS_H

#include "mdnspp/callback_types.h"

namespace mdnspp {

struct observer_options
{
    using record_callback = mdnspp::record_callback;
    using error_handler = mdnspp::error_handler;

    record_callback on_record{};
    error_handler on_error{};
};

}

#endif
