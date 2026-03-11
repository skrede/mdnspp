#ifndef HPP_GUARD_MDNSPP_QUERY_BACKOFF_H
#define HPP_GUARD_MDNSPP_QUERY_BACKOFF_H

#include "mdnspp/mdns_options.h"

#include <chrono>

namespace mdnspp::detail {

/// Mutable state for the exponential backoff scheduler (RFC 6762 §5.2).
///
/// Construct one instance per queried name/type pair. Pass it by reference to
/// @c advance_backoff at each scheduling point. Reset by reconstructing.
struct query_backoff_state
{
    std::chrono::milliseconds current_interval{};
    bool first{true};
};

/// Advance the backoff state and return the next wait interval.
///
/// On the first call @c s.first is cleared and @c opts.initial_interval is
/// returned. On every subsequent call the stored interval is multiplied by
/// @c opts.backoff_multiplier (using floating-point arithmetic to avoid
/// premature integer truncation) and clamped to @c opts.max_interval.
///
/// @param s     Backoff state for this query instance — modified in place.
/// @param opts  Protocol tunables; usually default-constructed.
/// @returns The duration to wait before sending the next query.
[[nodiscard]] inline std::chrono::milliseconds
advance_backoff(query_backoff_state &s, const mdns_options &opts) noexcept
{
    if(s.first)
    {
        s.first = false;
        s.current_interval = opts.initial_interval;
        return s.current_interval;
    }

    // Compute next interval in floating-point to avoid integer truncation at
    // small multipliers (e.g., 1.5× of 1000ms should give 1500ms, not 1000ms).
    using namespace std::chrono;
    auto next_fp = static_cast<double>(s.current_interval.count()) * opts.backoff_multiplier;
    auto next = duration_cast<milliseconds>(duration<double, std::milli>(next_fp));

    s.current_interval = (next < opts.max_interval) ? next : opts.max_interval;
    return s.current_interval;
}

}

#endif
