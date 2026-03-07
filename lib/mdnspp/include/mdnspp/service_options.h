#ifndef HPP_GUARD_MDNSPP_SERVICE_OPTIONS_H
#define HPP_GUARD_MDNSPP_SERVICE_OPTIONS_H

#include "mdnspp/endpoint.h"
#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_enums.h"

#include <chrono>
#include <string>

namespace mdnspp {

struct service_options
{
    using conflict_callback = detail::move_only_function<
        bool(const std::string &conflicting_name, std::string &new_name, unsigned attempt)>;

    conflict_callback on_conflict{};
    detail::move_only_function<void(const endpoint &sender, dns_type type, response_mode mode)> on_query{};
    unsigned announce_count{2};
    std::chrono::milliseconds announce_interval{1000};
};

}

#endif
