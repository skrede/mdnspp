#ifndef HPP_GUARD_MDNSPP_CACHE_OPTIONS_H
#define HPP_GUARD_MDNSPP_CACHE_OPTIONS_H

#include "mdnspp/cache_entry.h"

#include "mdnspp/detail/compat.h"

#include <chrono>
#include <vector>

namespace mdnspp {

struct cache_options
{
    detail::move_only_function<void(std::vector<cache_entry>)> on_expired{};
    detail::move_only_function<void(const cache_entry &, std::vector<cache_entry>)> on_cache_flush{};

    /// Grace period for goodbye records (TTL=0) before they are evicted from
    /// the cache (RFC 6762 §10.1).
    ///
    /// When a record is received with TTL=0 it is retained for this duration
    /// so that the application can observe the goodbye before eviction.
    ///
    /// RFC default: 1 second.
    ///
    /// Risk of changing: Reducing below 1 s may evict goodbye records before
    /// the application has a chance to process them. Increasing causes stale
    /// records to linger longer in the cache after a goodbye announcement.
    std::chrono::seconds goodbye_grace{1};
};

}

#endif
