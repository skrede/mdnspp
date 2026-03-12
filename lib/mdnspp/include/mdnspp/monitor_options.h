#ifndef HPP_GUARD_MDNSPP_MONITOR_OPTIONS_H
#define HPP_GUARD_MDNSPP_MONITOR_OPTIONS_H

#include "mdnspp/resolved_service.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_enums.h"

namespace mdnspp {

/// Query scheduling strategy for basic_service_monitor.
///
/// Controls whether and how the monitor issues automatic mDNS queries.
///
/// - @c observe     -- Passive only. No automatic queries are issued. Records
///                     are accumulated solely from overheard multicast traffic
///                     and expire naturally at TTL. Explicit query functions
///                     are the only way to trigger queries.
///
/// - @c ttl_refresh -- No discovery queries, but cached records are proactively
///                     refreshed at 80/85/90/95% TTL to keep known services
///                     alive. Records expire if the remote stops responding.
///
/// - @c discover    -- Full RFC 6762 section 5.2 continuous discovery.
///                     Per-type exponential backoff queries plus TTL refresh
///                     (default). Explicit query functions layer additional
///                     manual queries on top of automatic scheduling.
enum class monitor_mode
{
    observe,
    ttl_refresh,
    discover,
};

/// Discriminator for @c monitor_options::on_updated callbacks.
///
/// Indicates the direction of change for a record that altered a resolved service.
///
/// - @c added   -- A record was added or an existing field was modified
///                 (e.g., new address, changed TXT, new port).
///
/// - @c removed -- A record was removed without triggering full service loss
///                 (e.g., an address was lost while SRV is still alive).
enum class update_event
{
    added,
    removed,
};

/// Reason code delivered to @c monitor_options::on_lost callbacks.
///
/// - @c timeout    -- SRV record TTL expired without a refresh. Service is
///                    presumed gone.
///
/// - @c goodbye    -- A goodbye packet (TTL=0) was received. After the RFC 6762
///                    section 11.3 one-second grace period the service is
///                    considered lost.
///
/// - @c unwatched  -- The user called unwatch() for the service type. All
///                    tracked services of that type are reported as lost with
///                    this reason before their cache entries are purged.
enum class loss_reason
{
    timeout,
    goodbye,
    unwatched,
};

/// Configuration options for basic_service_monitor.
///
/// All fields default-construct to sensible values. Use designated initializers
/// to override selected fields:
/// @code
///   mdnspp::monitor_options opts{
///       .mode      = mdnspp::monitor_mode::observe,
///       .on_found  = [](const auto &svc) { ... },
///   };
/// @endcode
struct monitor_options
{
    /// Callback invoked once per fully-resolved service instance.
    ///
    /// Fires only when the minimum resolution threshold is met:
    /// PTR + SRV + at least one A or AAAA address record. Partial records are
    /// accumulated silently; users always receive a usable @c resolved_service.
    detail::move_only_function<void(const resolved_service &)> on_found{};

    /// Callback invoked when a record change alters an already-resolved service.
    ///
    /// Fires on additions (new address, changed TXT, new port) and on
    /// degradations (address removed, TXT removed) while the SRV anchor record
    /// is still alive. Does not fire on TTL refreshes with identical rdata.
    /// One callback fires per changed record type within a single packet.
    detail::move_only_function<void(const resolved_service &, update_event, dns_type)> on_updated{};

    /// Callback invoked when a service is no longer reachable.
    ///
    /// Fires when the SRV anchor record expires or is explicitly withdrawn.
    /// Delivers the last-known fully-resolved @c resolved_service together with
    /// the reason for loss.
    detail::move_only_function<void(const resolved_service &, loss_reason)> on_lost{};

    /// Query scheduling strategy.
    ///
    /// Controls automatic query issuance. See @c monitor_mode documentation.
    monitor_mode mode{monitor_mode::discover};
};

}

#endif
