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

    /// Default TTL (in seconds) for outgoing DNS resource records
    /// (RFC 6762 §11.3).
    ///
    /// Applied to all outgoing records unless overridden by a per-type TTL in
    /// @c service_options. Typically 75 minutes for most record types.
    ///
    /// RFC default: 4500 seconds (75 minutes).
    ///
    /// Risk of changing: Reducing this shortens the period during which
    /// resolvers cache the record, increasing query traffic. Increasing it
    /// delays propagation of address changes.
    std::chrono::seconds record_ttl{4500};

    /// Minimum random delay before sending a multicast response (RFC 6762 §6).
    ///
    /// When a response is scheduled, a random delay uniformly drawn from
    /// [response_delay_min, response_delay_max] is added to avoid simultaneous
    /// replies from multiple responders.
    ///
    /// RFC default: 20 ms.
    ///
    /// Risk of changing: Reducing below 20 ms increases collision probability
    /// on busy links. Increasing beyond 120 ms may cause noticeable latency in
    /// service discovery.
    std::chrono::milliseconds response_delay_min{20};

    /// Maximum random delay before sending a multicast response (RFC 6762 §6).
    ///
    /// See @c response_delay_min. The actual delay is uniformly sampled from
    /// [response_delay_min, response_delay_max].
    ///
    /// RFC default: 120 ms.
    ///
    /// Risk of changing: Increasing lengthens individual response latency;
    /// decreasing may cause response collisions on dense networks.
    std::chrono::milliseconds response_delay_max{120};

    /// TTL cap applied to all records sent in legacy unicast responses
    /// (RFC 6762 §6.7).
    ///
    /// When a query arrives via unicast from a port other than 5353 (legacy
    /// unicast), the TTL of all answer records is capped at this value to
    /// prevent aggressive caching by non-mDNS resolvers.
    ///
    /// RFC default: 10 seconds.
    ///
    /// Risk of changing: Increasing this allows legacy clients to cache records
    /// longer but violates the RFC recommendation to minimise non-mDNS cache
    /// pollution.
    std::chrono::seconds legacy_unicast_ttl{10};

    /// Fraction of the wire TTL used as the known-answer suppression threshold
    /// for standard multicast queries (RFC 6762 §7.1).
    ///
    /// A known answer is considered valid (and suppresses re-announcement) when
    /// its remaining TTL is at least @c wire_ttl * ka_suppression_fraction.
    /// The default 0.5 corresponds to the RFC threshold of half the original
    /// TTL (e.g., 2250 s for a 4500 s record).
    ///
    /// RFC default: 0.5 (half of wire TTL).
    ///
    /// Risk of changing: Lowering accepts stale known answers, increasing
    /// unnecessary suppressions. Raising causes more re-announcements.
    double ka_suppression_fraction{0.5};

    /// Fraction of the wire TTL used as the suppression threshold on the TC
    /// (truncated) accumulation path (RFC 6762 §7.1).
    ///
    /// Applied independently from @c ka_suppression_fraction so TC-path
    /// suppression can be tuned separately without affecting standard queries.
    ///
    /// RFC default: 0.5 (half of wire TTL).
    ///
    /// Risk of changing: Same trade-offs as @c ka_suppression_fraction but
    /// confined to the TC accumulation code path.
    double tc_suppression_fraction{0.5};

    /// Maximum UDP payload size (in bytes) for an outgoing query packet before
    /// it must be split into TC continuation packets.
    ///
    /// Matches the Ethernet MTU of 1500 bytes minus 20 bytes IPv4 header and
    /// 8 bytes UDP header. Reduce when operating over lower-MTU links (e.g.,
    /// IEEE 802.11 with A-MSDU aggregation overhead).
    ///
    /// RFC default: 1472 bytes.
    ///
    /// Risk of changing: Reducing forces earlier TC splits, increasing packet
    /// count. Increasing risks fragmentation on paths with smaller MTUs.
    std::size_t max_query_payload{1472};

    /// Delay inserted between successive TC continuation packets (RFC 6762 §6).
    ///
    /// Zero means packets are sent back-to-back as fast as the socket allows.
    /// A non-zero value rate-limits TC continuation bursts on congested links.
    ///
    /// RFC default: 0 (no added delay).
    ///
    /// Risk of changing: Adding delay slows down large known-answer list
    /// transmission but reduces burst congestion on busy networks.
    std::chrono::microseconds tc_continuation_delay{0};

    /// Minimum IP TTL (hop limit) for received mDNS packets (RFC 6762 §11).
    ///
    /// Packets arriving with an IP TTL below this value are silently discarded.
    /// The value 255 enforces link-local-only reception: any packet that has
    /// been forwarded by a router has its IP TTL decremented below 255.
    ///
    /// RFC default: 255 (link-local only).
    ///
    /// Risk of changing: Reducing below 255 allows packets forwarded by
    /// routers, which violates the mDNS link-local scoping requirement and
    /// enables cross-segment spoofing attacks.
    unsigned receive_ttl_minimum{255};
};

}

#endif
