#ifndef HPP_GUARD_MDNSPP_TTL_REFRESH_H
#define HPP_GUARD_MDNSPP_TTL_REFRESH_H

#include "mdnspp/mdns_options.h"

#include <chrono>
#include <vector>
#include <random>
#include <cstdint>
#include <optional>

namespace mdnspp::detail {

/// Precomputed schedule of time points at which refresh queries should be sent
/// for a cached record (RFC 6762 §5.2).
///
/// Fire points are derived from the wire TTL and the threshold fractions in
/// @c mdns_options::ttl_refresh_thresholds, with optional jitter applied.
/// Consumed sequentially via @c next_refresh_point.
///
/// @tparam Clock  A @c std::chrono clock type. Defaults to
///                @c std::chrono::steady_clock; substitute
///                @c mdnspp::testing::test_clock in unit tests.
template <typename Clock = std::chrono::steady_clock>
struct ttl_refresh_schedule
{
    /// Ascending list of absolute time points at which to issue a refresh query.
    std::vector<typename Clock::time_point> fire_at{};

    /// Index of the next unconsumed fire point.
    std::size_t next_idx{0};
};

/// Build a refresh schedule for a cached record.
///
/// For each threshold @c t in @c opts.ttl_refresh_thresholds a fire point is
/// computed as:
/// @code
///   inserted_at + (wire_ttl_seconds * 1000.0 * t) ms
///                + uniform_random([0, wire_ttl_seconds * 1000.0 * jitter_pct]) ms
/// @endcode
///
/// Fire points are emitted in threshold order (which is ascending by
/// convention). The caller is responsible for sorting @c ttl_refresh_thresholds
/// if a custom, non-ascending order is undesirable.
///
/// @param wire_ttl_seconds  The TTL value as received on the wire, in seconds.
/// @param opts              Protocol tunables; reads @c ttl_refresh_thresholds
///                          and @c refresh_jitter_pct.
/// @param inserted_at       The time at which the record was (re-)inserted into
///                          the cache — the base time for all offsets.
/// @param rng               A seeded Mersenne-Twister RNG. The caller controls
///                          the seed to allow deterministic testing.
/// @returns A fully computed @c ttl_refresh_schedule ready for consumption.
template <typename Clock = std::chrono::steady_clock>
[[nodiscard]] inline ttl_refresh_schedule<Clock>
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

/// Return and consume the next pending refresh fire point.
///
/// Advances @c sched.next_idx on success.
///
/// @returns The next @c time_point, or @c std::nullopt if the schedule is
///          exhausted.
template <typename Clock>
[[nodiscard]] inline std::optional<typename Clock::time_point>
next_refresh_point(ttl_refresh_schedule<Clock> &sched)
{
    if(sched.next_idx >= sched.fire_at.size())
        return std::nullopt;

    return sched.fire_at[sched.next_idx++];
}

/// Return @c true if there are unconsumed fire points remaining.
template <typename Clock>
[[nodiscard]] inline bool has_pending(const ttl_refresh_schedule<Clock> &sched) noexcept
{
    return sched.next_idx < sched.fire_at.size();
}

}

#endif
