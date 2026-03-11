#ifndef HPP_GUARD_MDNSPP_QUERY_OPTIONS_H
#define HPP_GUARD_MDNSPP_QUERY_OPTIONS_H

#include "mdnspp/callback_types.h"

#include <chrono>

namespace mdnspp {

struct query_options
{
    using record_callback = mdnspp::record_callback;

    record_callback on_record{};
    std::chrono::milliseconds silence_timeout{3000};
};

}

#endif
