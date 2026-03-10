#ifndef HPP_GUARD_MDNSPP_OBSERVER_OPTIONS_H
#define HPP_GUARD_MDNSPP_OBSERVER_OPTIONS_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/detail/compat.h"

namespace mdnspp {

struct observer_options
{
    using record_callback = detail::move_only_function<void(const endpoint &, const mdns_record_variant &)>;

    record_callback on_record{};
};

}

#endif
