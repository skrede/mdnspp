#ifndef HPP_GUARD_MDNSPP_CACHE_OPTIONS_H
#define HPP_GUARD_MDNSPP_CACHE_OPTIONS_H

#include "mdnspp/cache_entry.h"

#include "mdnspp/detail/compat.h"

#include <chrono>
#include <vector>

namespace mdnspp {

struct cache_options
{
    move_only_function<void(std::vector<cache_entry>)> on_expired{};
    move_only_function<void(const cache_entry &, std::vector<cache_entry>)> on_cache_flush{};
    std::chrono::seconds goodbye_grace{1};
};

}

#endif
