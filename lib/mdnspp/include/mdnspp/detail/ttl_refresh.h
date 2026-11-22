#ifndef HPP_GUARD_MDNSPP_DETAIL_TTL_REFRESH_H
#define HPP_GUARD_MDNSPP_DETAIL_TTL_REFRESH_H

#include "mdnspp/mdns_options.h"

#include <chrono>
#include <random>
#include <vector>
#include <cstdint>
#include <optional>

namespace mdnspp::detail {

// RFC 6762 section 5.2: refresh queries at fractions of the record's wire TTL.
template <typename Clock = std::chrono::steady_clock>
struct ttl_refresh_schedule
{
    std::vector<typename Clock::time_point> fire_at{};
    std::size_t next_idx{0};
};

// Fire points keep the order of ttl_refresh_thresholds, which validation requires to be strictly increasing;
// only jitter can put a fire point before its predecessor.
template <typename Clock = std::chrono::steady_clock>
inline ttl_refresh_schedule<Clock>
make_refresh_schedule(uint32_t wire_ttl_seconds,
                      const mdns_options &opts,
                      typename Clock::time_point inserted_at,
                      std::mt19937 &rng)
{
    ttl_refresh_schedule<Clock> sched;
    sched.fire_at.reserve(opts.ttl_refresh_thresholds.size());

    const double wire_ms = static_cast<double>(wire_ttl_seconds) * 1000.0;
    const double max_jitter_ms = wire_ms * opts.refresh_jitter_pct;

    std::uniform_real_distribution<double> jitter_dist{0.0, max_jitter_ms};

    for(double threshold : opts.ttl_refresh_thresholds)
    {
        double offset_ms = wire_ms * threshold;
        if(max_jitter_ms > 0.0)
            offset_ms += jitter_dist(rng);

        using namespace std::chrono;
        auto offset = duration_cast<typename Clock::duration>(duration<double, std::milli>(offset_ms));
        sched.fire_at.push_back(inserted_at + offset);
    }

    return sched;
}

template <typename Clock>
inline std::optional<typename Clock::time_point>
next_refresh_point(ttl_refresh_schedule<Clock> &sched)
{
    if(sched.next_idx >= sched.fire_at.size())
        return std::nullopt;

    return sched.fire_at[sched.next_idx++];
}

template <typename Clock>
inline bool has_pending(const ttl_refresh_schedule<Clock> &sched) noexcept
{
    return sched.next_idx < sched.fire_at.size();
}

}

#endif
