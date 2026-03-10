#ifndef HPP_GUARD_MDNSPP_QUERY_OPTIONS_H
#define HPP_GUARD_MDNSPP_QUERY_OPTIONS_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/detail/compat.h"

#include <chrono>

namespace mdnspp {

struct query_options
{
    using record_callback = detail::move_only_function<void(const endpoint &, const mdns_record_variant &)>;

    record_callback on_record{};
    std::chrono::milliseconds silence_timeout{3000};
};

}

#endif
