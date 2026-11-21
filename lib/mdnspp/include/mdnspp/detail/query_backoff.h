#ifndef HPP_GUARD_MDNSPP_DETAIL_QUERY_BACKOFF_H
#define HPP_GUARD_MDNSPP_DETAIL_QUERY_BACKOFF_H

#include "mdnspp/mdns_options.h"

#include <chrono>

namespace mdnspp::detail {

// RFC 6762 §5.2 exponential query backoff.
struct query_backoff_state
{
    std::chrono::milliseconds current_interval{};
    bool first{true};
};

inline std::chrono::milliseconds
advance_backoff(query_backoff_state &s, const mdns_options &opts) noexcept
{
    if(s.first)
    {
        s.first = false;
        s.current_interval = opts.initial_interval;
        return s.current_interval;
    }

    // Floating point, so that a fractional multiplier is not truncated (1.5 x 1000 ms is 1500 ms, not 1000 ms).
    using namespace std::chrono;
    auto next_fp = static_cast<double>(s.current_interval.count()) * opts.backoff_multiplier;
    auto next = duration_cast<milliseconds>(duration<double, std::milli>(next_fp));

    s.current_interval = (next < opts.max_interval) ? next : opts.max_interval;
    return s.current_interval;
}

}

#endif
