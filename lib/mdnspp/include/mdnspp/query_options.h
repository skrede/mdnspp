#ifndef HPP_GUARD_MDNSPP_QUERY_OPTIONS_H
#define HPP_GUARD_MDNSPP_QUERY_OPTIONS_H

#include "mdnspp/callback_types.h"

#include <chrono>

namespace mdnspp {

struct query_options
{
    using record_callback = mdnspp::record_callback;
    using error_handler = mdnspp::error_handler;

    record_callback on_record{};
    error_handler on_error{};
    std::chrono::milliseconds silence_timeout{3000};
};

}

#endif
