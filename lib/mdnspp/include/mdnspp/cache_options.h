#ifndef HPP_GUARD_MDNSPP_CACHE_OPTIONS_H
#define HPP_GUARD_MDNSPP_CACHE_OPTIONS_H

#include "mdnspp/cache_entry.h"

#include "mdnspp/detail/compat.h"

#include <vector>

namespace mdnspp {

struct cache_options
{
    detail::move_only_function<void(std::vector<cache_entry>)> on_expired{};
    detail::move_only_function<void(const cache_entry &, std::vector<cache_entry>)> on_cache_flush{};
};

}

#endif
