#ifndef HPP_GUARD_MDNSPP_MDNS_OPTIONS_H
#define HPP_GUARD_MDNSPP_MDNS_OPTIONS_H

#include <chrono>
#include <vector>
#include <cstddef>

namespace mdnspp {

/// Protocol tunables for RFC 6762 continuous querying, TTL refresh scheduling,
/// and truncated-response accumulation.
///
/// All fields are defaulted to RFC-compliant values. Changing them is an
/// advanced operation: incorrect settings may violate interoperability
/// guarantees or cause excessive network traffic.
///
/// Designed to be used as a designated-initializer-compatible struct, e.g.:
/// @code
///   mdns_options opts{.initial_interval = std::chrono::milliseconds{500}};
/// @endcode
struct mdns_options
{
    /// Starting interval for the exponential query backoff (RFC 6762 §5.2).
    ///
    /// The first query is issued immediately; the next is scheduled after this
    /// delay, doubling each time until @c max_interval is reached.
    ///
    /// RFC default: 1 second.
    ///
    /// Risk of changing: Reducing below 1 s may produce a flood of queries on
    /// crowded networks. Increasing excessively delays initial discovery.
    std::chrono::milliseconds initial_interval{std::chrono::seconds(1)};

    /// Upper bound on the exponential backoff interval (RFC 6762 §5.2).
    ///
    /// Once the computed interval exceeds this value it is clamped here and
    /// the backoff stops growing.
    ///
    /// RFC default: 1 hour.
    ///
    /// Risk of changing: Reducing to seconds or minutes is appropriate for
    /// dense, fast-changing networks (e.g., robotics middleware) but increases
    /// steady-state query traffic proportionally.
    std::chrono::milliseconds max_interval{std::chrono::hours(1)};

    /// Multiplicative factor applied to the current interval on each backoff
    /// step (RFC 6762 §5.2).
    ///
    /// RFC default: 2.0 (doubling).
    ///
    /// Risk of changing: Values below 1.0 cause the interval to shrink,
    /// producing unbounded query storms. Values much larger than 2.0 reach
    /// @c max_interval extremely quickly, making backoff effectively binary.
    double backoff_multiplier{2.0};

    /// Fractional TTL thresholds at which refresh queries are issued
    /// (RFC 6762 §5.2).
    ///
    /// Each value represents the fraction of the wire TTL elapsed since record
    /// insertion at which a refresh query is sent. Values must be in (0, 1)
    /// and should be strictly increasing. The refresh schedule is cancelled as
    /// soon as a fresh record is received.
    ///
    /// RFC default: {0.80, 0.85, 0.90, 0.95} — four refresh attempts covering
    /// the last 20% of the TTL window.
    ///
    /// Risk of changing: Fewer thresholds means fewer retries before expiry;
    /// earlier thresholds increase unnecessary query traffic.
    std::vector<double> ttl_refresh_thresholds{0.80, 0.85, 0.90, 0.95};

    /// Maximum jitter applied to each refresh query fire point as a fraction
    /// of the wire TTL (RFC 6762 §5.2).
    ///
    /// A uniform random offset in [0, wire_ttl * refresh_jitter_pct] is added
    /// to each threshold-derived time point to desynchronise simultaneous
    /// queriers on the same segment.
    ///
    /// RFC default: 0.02 (2%).
    ///
    /// Risk of changing: Setting to 0.0 disables jitter entirely, which may
    /// cause query storms when many nodes monitor the same records.
    double refresh_jitter_pct{0.02};

    /// Minimum wait duration for accumulating truncated-response continuation
    /// packets (RFC 6762 §6).
    ///
    /// When a query arrives with the TC (truncation) bit set, the responder
    /// waits up to a random duration in [tc_wait_min, tc_wait_max] before
    /// processing the aggregated known-answer set.
    ///
    /// RFC default: 400 ms.
    ///
    /// Risk of changing: Reducing below 400 ms may cause premature response
    /// before all continuation packets have arrived on slow links.
    std::chrono::milliseconds tc_wait_min{400};

    /// Maximum wait duration for accumulating truncated-response continuation
    /// packets (RFC 6762 §6).
    ///
    /// See @c tc_wait_min. The actual wait is uniformly sampled from
    /// [tc_wait_min, tc_wait_max] per RFC recommendation.
    ///
    /// RFC default: 500 ms.
    ///
    /// Risk of changing: Increasing lengthens known-answer collection but
    /// delays responses visible to queriers on the network.
    std::chrono::milliseconds tc_wait_max{500};

    /// Maximum number of known-answer records included in outgoing queries
    /// (RFC 6762 §7.1).
    ///
    /// When non-zero, limits the known-answer list in multi-question queries
    /// to this many records (selected by highest remaining TTL first).
    /// Zero means unlimited — all qualifying records are included.
    ///
    /// RFC default: 0 (unlimited).
    ///
    /// Risk of changing: Setting a low cap may cause responders to re-announce
    /// records that the querier already holds, increasing traffic slightly.
    std::size_t max_known_answers{0};
};

}

#endif
