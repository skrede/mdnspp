#ifndef HPP_GUARD_MDNSPP_DETAIL_MDNS_OPTIONS_VALIDATION_H
#define HPP_GUARD_MDNSPP_DETAIL_MDNS_OPTIONS_VALIDATION_H

#include "mdnspp/mdns_options.h"

#include <algorithm>
#include <functional>
#include <system_error>

namespace mdnspp::detail {

inline bool invalid_timing_ranges(const mdns_options &opts) noexcept
{
    return opts.response_delay_min.count() < 0 || opts.response_delay_min > opts.response_delay_max
        || opts.tc_wait_min.count() < 0 || opts.tc_wait_min > opts.tc_wait_max;
}

inline bool invalid_backoff(const mdns_options &opts) noexcept
{
    return opts.initial_interval.count() <= 0 || opts.max_interval < opts.initial_interval
        || opts.backoff_multiplier < 1.0 || opts.refresh_jitter_pct < 0.0;
}

inline bool invalid_fraction(double fraction) noexcept
{
    return fraction <= 0.0 || fraction >= 1.0;
}

inline bool invalid_suppression_fractions(const mdns_options &opts) noexcept
{
    return invalid_fraction(opts.ka_suppression_fraction) || invalid_fraction(opts.tc_suppression_fraction);
}

inline bool invalid_refresh_thresholds(const mdns_options &opts) noexcept
{
    const auto &thresholds = opts.ttl_refresh_thresholds;
    return std::ranges::any_of(thresholds, invalid_fraction)
        || std::ranges::adjacent_find(thresholds, std::greater_equal<>{}) != thresholds.end();
}

inline std::error_code validate_mdns_options(const mdns_options &opts) noexcept
{
    if(invalid_timing_ranges(opts) || invalid_backoff(opts) || invalid_suppression_fractions(opts)
       || invalid_refresh_thresholds(opts) || opts.qu_response_window.count() <= 0)
        return std::make_error_code(std::errc::invalid_argument);
    return {};
}

}

#endif
