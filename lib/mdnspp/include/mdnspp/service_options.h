#ifndef HPP_GUARD_MDNSPP_SERVICE_OPTIONS_H
#define HPP_GUARD_MDNSPP_SERVICE_OPTIONS_H

#include "mdnspp/endpoint.h"
#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_enums.h"

#include <chrono>
#include <string>
#include <cstdint>

namespace mdnspp {

struct service_options
{
    using conflict_callback = detail::move_only_function<
        bool(const std::string &conflicting_name, std::string &new_name, unsigned attempt, conflict_type type)>;

    conflict_callback on_conflict{};
    detail::move_only_function<void(const endpoint &sender, dns_type type, response_mode mode)> on_query{};
    /// Fired when TC continuation is processed: reports sender and number of accumulated continuation packets.
    detail::move_only_function<void(const endpoint &sender, std::size_t continuation_count)> on_tc_continuation{};
    uint8_t announce_count{2};
    std::chrono::milliseconds announce_interval{1000};
    bool send_goodbye{true};
    bool suppress_known_answers{true};
    bool respond_to_meta_queries{true};
    bool announce_subtypes{false};

    /// Number of probe packets sent before a service is considered
    /// conflict-free and announcing begins (RFC 6762 §8.1).
    ///
    /// RFC default: 3.
    ///
    /// Risk of changing: Reducing speeds up startup but increases the chance
    /// of a name conflict going undetected. Values below 1 skip probing
    /// entirely, which is non-compliant.
    uint8_t probe_count{3};

    /// Interval between successive probe packets (RFC 6762 §8.1).
    ///
    /// RFC default: 250 ms.
    ///
    /// Risk of changing: Reducing increases collision detection speed but
    /// adds more traffic; increasing delays service announcement.
    std::chrono::milliseconds probe_interval{250};

    /// Upper bound on the random initial delay before the first probe is sent
    /// (RFC 6762 §8.1).
    ///
    /// The first probe is delayed by a uniform random value in
    /// [0, probe_initial_delay_max] to desynchronise simultaneous startups.
    ///
    /// RFC default: 250 ms.
    ///
    /// Risk of changing: Reducing to zero means all nodes on the same segment
    /// that start simultaneously will probe at the same instant, causing
    /// collisions and unnecessary conflict resolution.
    std::chrono::milliseconds probe_initial_delay_max{250};

    /// Whether to respond to legacy unicast queries (RFC 6762 §6.7).
    ///
    /// Legacy unicast queries arrive from source port != 5353. Enabling this
    /// causes the responder to send a unicast reply with TTLs capped at
    /// @c mdns_options::legacy_unicast_ttl.
    ///
    /// RFC default: true (respond to legacy unicast).
    ///
    /// Risk of changing: Disabling silences the service for resolvers that
    /// use legacy DNS-SD querying (e.g., some Windows implementations).
    bool respond_to_legacy_unicast{true};

    /// TTL for PTR records in outgoing responses (RFC 6762 §11.3).
    ///
    /// RFC default: 4500 seconds (75 minutes).
    ///
    /// Risk of changing: Reducing shortens how long queriers retain the
    /// service discovery entry, increasing re-query frequency.
    std::chrono::seconds ptr_ttl{4500};

    /// TTL for SRV records in outgoing responses (RFC 6762 §11.3).
    ///
    /// RFC default: 4500 seconds (75 minutes).
    ///
    /// Risk of changing: Reducing causes resolvers to re-query the host/port
    /// mapping more frequently.
    std::chrono::seconds srv_ttl{4500};

    /// TTL for TXT records in outgoing responses (RFC 6762 §11.3).
    ///
    /// RFC default: 4500 seconds (75 minutes).
    ///
    /// Risk of changing: Reducing causes resolvers to re-query metadata more
    /// frequently; increasing delays propagation of attribute changes.
    std::chrono::seconds txt_ttl{4500};

    /// TTL for A records in outgoing responses (RFC 6762 §11.3).
    ///
    /// RFC default: 4500 seconds (75 minutes).
    ///
    /// Risk of changing: Reducing causes resolvers to re-query IPv4 addresses
    /// more frequently; care should be taken on networks with dynamic addressing.
    std::chrono::seconds a_ttl{4500};

    /// TTL for AAAA records in outgoing responses (RFC 6762 §11.3).
    ///
    /// RFC default: 4500 seconds (75 minutes).
    ///
    /// Risk of changing: Same trade-offs as @c a_ttl but for IPv6 addresses.
    std::chrono::seconds aaaa_ttl{4500};

    /// Fallback TTL used for NSEC and meta-query PTR records when no
    /// per-record-type TTL is applicable (RFC 6762 §11.3).
    ///
    /// RFC default: 4500 seconds (75 minutes).
    ///
    /// Risk of changing: This is the last-resort TTL; reducing it increases
    /// re-query frequency for these secondary records.
    std::chrono::seconds record_ttl{4500};

    /// TTL for SRV records placed in the authority section of probe queries
    /// (RFC 6762 §8.2).
    ///
    /// The authority SRV record is used for simultaneous-probe tiebreaking.
    /// Its TTL is not cached by recipients but must be a valid non-zero value.
    ///
    /// RFC default: 120 seconds.
    ///
    /// Risk of changing: This value is effectively ignored by recipients in
    /// the tiebreaking context; changing it has no interoperability impact.
    std::chrono::seconds probe_authority_ttl{120};

    /// Delay before re-probing after losing a simultaneous-probe tiebreak
    /// (RFC 6762 §8.2).
    ///
    /// When the tiebreaking comparison indicates the remote probe wins, the
    /// local node defers by this duration before restarting its probe sequence.
    ///
    /// RFC default: 1000 ms (1 second).
    ///
    /// Risk of changing: Reducing to zero may cause a rapid storm of re-probes
    /// if multiple nodes start simultaneously. Increasing delays service startup.
    std::chrono::milliseconds probe_defer_delay{1000};
};

}

#endif
