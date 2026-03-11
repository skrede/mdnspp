#ifndef HPP_GUARD_MDNSPP_BASIC_SERVICE_MONITOR_H
#define HPP_GUARD_MDNSPP_BASIC_SERVICE_MONITOR_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/cache_entry.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/record_cache.h"
#include "mdnspp/cache_options.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/monitor_options.h"
#include "mdnspp/resolved_service.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_wire.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_query.h"
#include "mdnspp/detail/recv_loop.h"
#include "mdnspp/detail/ttl_refresh.h"
#include "mdnspp/detail/query_backoff.h"
#include "mdnspp/detail/basic_mdns_peer_base.h"

#include <span>
#include <atomic>
#include <chrono>
#include <memory>
#include <random>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <algorithm>
#include <system_error>
#include <unordered_map>
#include <unordered_set>

namespace mdnspp {

// basic_service_monitor<P, Clock> -- continuous, TTL-aware mDNS service tracker
//
// Policy-based class template parameterized on:
//   P     -- Policy: provides executor_type, socket_type, timer_type
//   Clock -- Clock type (default: std::chrono::steady_clock). Substitute
//            mdnspp::testing::test_clock in unit tests for deterministic TTL control.
//
// Lifecycle:
//   1. Construct with (ex, opts, sock_opts, mdns_opts) or non-throwing overload
//   2. watch(service_type) -- register interest in a service type
//   3. async_start(on_done) -- begin receiving and querying
//   4. stop() -- idempotent; cancels all timers and receives
//   5. ~basic_service_monitor() -- calls stop() for RAII safety
//
// Thread safety:
//   watch(), unwatch(), query_service_type(), query_service_instance(), and
//   services() may be called from any thread. All mutations are posted to the
//   executor thread via P::post() using a weak_ptr guard.

template <Policy P, typename Clock = std::chrono::steady_clock>
class basic_service_monitor : detail::basic_mdns_peer_base<P>
{
    using base = detail::basic_mdns_peer_base<P>;

public:
    using typename base::executor_type;
    using typename base::socket_type;
    using typename base::timer_type;
    using base::socket;

    // Non-copyable, non-movable
    basic_service_monitor(const basic_service_monitor &) = delete;
    basic_service_monitor &operator=(const basic_service_monitor &) = delete;
    basic_service_monitor(basic_service_monitor &&) = delete;
    basic_service_monitor &operator=(basic_service_monitor &&) = delete;

    /// Throwing constructor.
    ///
    /// @param ex         Executor to use for async operations.
    /// @param opts       Monitor options (callbacks, mode). Move-only.
    /// @param sock_opts  Socket configuration (multicast group, interface, etc.).
    /// @param mdns_opts  Protocol tunables (backoff, TTL refresh, TC wait).
    explicit basic_service_monitor(executor_type ex,
                                   monitor_options opts = {},
                                   socket_options sock_opts = {},
                                   mdns_options mdns_opts = {})
        : base(ex, sock_opts, std::move(mdns_opts))
        , m_scheduler_timer(ex)
        , m_opts(std::move(opts))
        , m_cache(make_cache_options())
        , m_rng(std::random_device{}())
    {
    }

    /// Non-throwing constructor.
    ///
    /// On socket construction failure @p ec is set and the object is left in a
    /// safe but unusable state. Check @p ec before calling async_start().
    ///
    /// @param ex         Executor to use for async operations.
    /// @param opts       Monitor options (callbacks, mode). Move-only.
    /// @param sock_opts  Socket configuration.
    /// @param mdns_opts  Protocol tunables.
    /// @param ec         Receives the error code on failure, cleared on success.
    basic_service_monitor(executor_type ex,
                          monitor_options opts,
                          socket_options sock_opts,
                          mdns_options mdns_opts,
                          std::error_code &ec)
        : base(ex, sock_opts, std::move(mdns_opts), ec)
        , m_scheduler_timer(ex)
        , m_opts(std::move(opts))
        , m_cache(make_cache_options())
        , m_rng(std::random_device{}())
    {
    }

    ~basic_service_monitor()
    {
        stop();
    }

    // -------------------------------------------------------------------------
    // Public interface
    // -------------------------------------------------------------------------

    /// Begin receiving mDNS multicast traffic and, depending on the configured
    /// @c monitor_mode, issuing discovery queries for watched service types.
    ///
    /// @p on_done fires once when stop() is called. May be @c nullptr.
    ///
    /// Calling async_start() more than once is a logic error.
    void async_start(detail::move_only_function<void(std::error_code)> on_done = {})
    {
        m_on_done = std::move(on_done);

        // Create the recv_loop with an "infinite" silence timeout.
        // The monitor has no silence semantics -- it runs until stop().
        using hours = std::chrono::hours;
        constexpr auto infinite = std::chrono::duration_cast<std::chrono::milliseconds>(
            hours{24 * 365});

        this->m_loop = std::make_unique<recv_loop<P>>(
            this->m_socket,
            this->m_timer,
            infinite,
            [this](const endpoint &sender, std::span<std::byte> data) -> bool
            {
                return handle_packet(sender, data);
            },
            [] { /* silence handler -- no-op for monitor */ });

        this->m_loop->start();
        arm_scheduler();
    }

    /// Stop the monitor. Idempotent. Posts teardown to the executor thread.
    void stop()
    {
        base::stop([this]()
        {
            m_scheduler_timer.cancel();
            if(this->m_loop)
                this->m_loop->stop();
            if(m_on_done)
            {
                auto cb = std::exchange(m_on_done, {});
                cb(std::error_code{});
            }
        });
    }

    /// Register interest in a service type (e.g., "_http._tcp.local").
    ///
    /// Thread-safe: posts the registration to the executor thread. Safe to call
    /// before async_start() -- the posted work queues until the executor runs.
    ///
    /// Re-watching a previously unwatched type starts fresh: backoff resets and
    /// on_found fires again on rediscovery.
    void watch(std::string service_type)
    {
        auto guard = std::weak_ptr<bool>(this->m_alive);
        P::post(this->m_executor, [this, guard, svc = std::move(service_type)]() mutable
        {
            if(!guard.lock()) return;
            do_watch(std::move(svc));
        });
    }

    /// Deregister interest in a service type.
    ///
    /// Fires on_lost(service, loss_reason::unwatched) for every currently-tracked
    /// service of this type, then purges their cache entries and backoff state.
    ///
    /// Thread-safe: posts to executor thread.
    void unwatch(std::string service_type)
    {
        auto guard = std::weak_ptr<bool>(this->m_alive);
        P::post(this->m_executor, [this, guard, svc = std::move(service_type)]() mutable
        {
            if(!guard.lock()) return;
            do_unwatch(std::move(svc));
        });
    }

    /// Return a snapshot of all currently-resolved services.
    ///
    /// Lock-free on the reader side (atomic shared_ptr load). Always returns a
    /// consistent, immutable vector. Empty before any services are discovered.
    std::vector<resolved_service> services() const
    {
        auto snap = m_services_snapshot.load(std::memory_order_acquire);
        if(snap)
            return *snap;
        return {};
    }

    /// Send an immediate PTR query for a service type, bypassing backoff.
    ///
    /// Available in all @c monitor_mode values. In @c discover mode this
    /// supplements the automatic schedule; in @c observe mode it is the only
    /// way to trigger a query.
    ///
    /// Thread-safe: posts to executor thread.
    void query_service_type(std::string service_type)
    {
        auto guard = std::weak_ptr<bool>(this->m_alive);
        P::post(this->m_executor, [this, guard, svc = std::move(service_type)]() mutable
        {
            if(!guard.lock()) return;
            send_ptr_query(svc);
        });
    }

    /// Send immediate SRV and A/AAAA queries for a specific service instance.
    ///
    /// Thread-safe: posts to executor thread.
    void query_service_instance(std::string instance_name)
    {
        auto guard = std::weak_ptr<bool>(this->m_alive);
        P::post(this->m_executor, [this, guard, inst = std::move(instance_name)]() mutable
        {
            if(!guard.lock()) return;
            send_instance_queries(inst);
        });
    }

    /// Trigger an expiry check -- intended for use in tests with a controlled Clock.
    ///
    /// In production, the scheduler timer calls erase_expired() periodically.
    /// This method provides an explicit hook for deterministic TTL tests using
    /// test_clock::advance() + tick_expired_for_test().
    void tick_expired_for_test()
    {
        auto expired = m_cache.erase_expired();
        // handle_expired is called by the cache's on_expired callback,
        // which fires inside erase_expired() -- nothing more needed here.
        (void)expired;
    }

    /// Test-support accessor for the dedicated scheduler timer.
    ///
    /// Allows unit tests to fire or inspect the scheduler timer without
    /// exposing it through the public API.
    timer_type &scheduler_timer_for_test() noexcept { return m_scheduler_timer; }

private:
    // -------------------------------------------------------------------------
    // Private constructor helpers
    // -------------------------------------------------------------------------

    /// Builds the cache_options for the constructor initializer list.
    /// Called before m_opts is initialized, so uses the (moved) opts only for
    /// wiring expiry -- the callback captures this, which is valid as soon as
    /// the base sub-object is alive.
    cache_options make_cache_options()
    {
        cache_options copts;
        copts.on_expired = [this](std::vector<cache_entry> expired)
        {
            handle_expired(std::move(expired));
        };
        return copts;
    }

    // -------------------------------------------------------------------------
    // Internal structs
    // -------------------------------------------------------------------------

    /// Incremental resolution state for a service instance whose full record set
    /// has not yet been received. Keyed by instance name in @c m_partial.
    struct incomplete_instance
    {
        std::string service_type;
        bool has_srv{false};
        bool has_address{false};
        resolved_service partial;
    };

    /// Per watched service-type state: independent backoff schedule and query
    /// timing. Keyed by service type string in @c m_watches.
    struct watched_type_state
    {
        detail::query_backoff_state backoff;
    };

    // -------------------------------------------------------------------------
    // Private methods -- packet processing pipeline
    // -------------------------------------------------------------------------

    /// Entry point for all incoming mDNS packets from the recv_loop.
    /// Returns true if the packet contained at least one relevant record
    /// (used by recv_loop to reset the silence timer, though the monitor
    /// always uses an infinite silence timeout).
    bool handle_packet(const endpoint &sender, std::span<std::byte> data)
    {
        bool relevant{false};
        detail::walk_dns_frame(data, sender, [&](mdns_record_variant rec)
        {
            if(!is_relevant(rec))
                return;
            relevant = true;
            m_cache.insert(rec, sender);
            process_record(std::move(rec));
        });
        return relevant;
    }

    /// Returns true if this record should be processed, false to silently drop.
    ///
    /// Filtering rules per MON-07:
    ///   PTR    -- accepted only if name is in m_watches
    ///   SRV    -- accepted if name is in m_partial or m_live_services
    ///   TXT    -- accepted if name is in m_partial or m_live_services
    ///   A/AAAA -- accepted if name is in m_known_hostnames
    bool is_relevant(const mdns_record_variant &rec) const
    {
        return std::visit([this](const auto &r) -> bool
        {
            using T = std::remove_cvref_t<decltype(r)>;

            if constexpr (std::is_same_v<T, record_ptr>)
                return m_watches.contains(r.name);
            else if constexpr (std::is_same_v<T, record_srv> || std::is_same_v<T, record_txt>)
                return m_partial.contains(r.name) || m_live_services.contains(r.name);
            else if constexpr (std::is_same_v<T, record_a> || std::is_same_v<T, record_aaaa>)
                return m_known_hostnames.contains(r.name);
            else
                return false;
        }, rec);
    }

    /// Dispatch to per-record-type processing logic.
    void process_record(mdns_record_variant rec)
    {
        std::visit([this](auto &&r)
        {
            using T = std::remove_cvref_t<decltype(r)>;

            if constexpr (std::is_same_v<T, record_ptr>)
                process_ptr(std::forward<decltype(r)>(r));
            else if constexpr (std::is_same_v<T, record_srv>)
                process_srv(std::forward<decltype(r)>(r));
            else if constexpr (std::is_same_v<T, record_a>)
                process_a(std::forward<decltype(r)>(r));
            else if constexpr (std::is_same_v<T, record_aaaa>)
                process_aaaa(std::forward<decltype(r)>(r));
            else if constexpr (std::is_same_v<T, record_txt>)
                process_txt(std::forward<decltype(r)>(r));
        }, std::move(rec));
    }

    /// PTR record: seed an incomplete_instance in m_partial if not already
    /// partial or live. The PTR.ptr_name becomes the instance name.
    void process_ptr(const record_ptr &r)
    {
        const std::string &inst = r.ptr_name;

        if(m_partial.contains(inst) || m_live_services.contains(inst))
            return; // already tracking or live -- no re-seed

        auto &partial = m_partial[inst];
        partial.service_type          = r.name;  // e.g. "_http._tcp.local"
        partial.partial.instance_name = inst;
        m_instance_type[inst]         = r.name;
    }

    /// SRV record: update partial with hostname+port; add hostname to
    /// m_known_hostnames so subsequent A/AAAA records are accepted.
    void process_srv(const record_srv &r)
    {
        // Track goodbye: TTL=0 marks this instance for goodbye reporting
        if(r.ttl == 0)
            m_goodbye_instances.insert(r.name);

        if(auto it = m_partial.find(r.name); it != m_partial.end())
        {
            it->second.has_srv             = true;
            it->second.partial.hostname    = r.srv_name;
            it->second.partial.port        = r.port;
            m_known_hostnames.insert(r.srv_name);
            // Build SRV refresh schedule now that we have the wire TTL
            if(r.ttl > 0)
                rebuild_refresh_schedule(r.name + ":srv", r.ttl);
            check_resolved(r.name);
        }
        else if(auto lit = m_live_services.find(r.name); lit != m_live_services.end())
        {
            // SRV TTL refresh for an already-live service: rebuild schedule and update
            if(r.ttl > 0)
                rebuild_refresh_schedule(r.name + ":srv", r.ttl);

            bool changed = (lit->second.hostname != r.srv_name || lit->second.port != r.port);
            if(changed)
            {
                lit->second.hostname = r.srv_name;
                lit->second.port     = r.port;
                m_known_hostnames.insert(r.srv_name);
                if(m_opts.on_updated)
                    m_opts.on_updated(lit->second, update_event::added, dns_type::srv);
                update_snapshot();
            }
        }
    }

    /// A record: add IPv4 address to partial/live service.
    void process_a(const record_a &r)
    {
        // Check partial first -- any instance using this hostname
        bool any_updated{false};

        for(auto &[inst_name, inc] : m_partial)
        {
            if(inc.partial.hostname == r.name)
            {
                if(std::ranges::find(inc.partial.ipv4_addresses, r.address_string)
                   == inc.partial.ipv4_addresses.end())
                {
                    inc.partial.ipv4_addresses.push_back(r.address_string);
                    inc.has_address = true;
                    any_updated     = true;
                }
            }
        }

        if(any_updated)
        {
            // Try to resolve any partial that may now be complete
            std::vector<std::string> to_check;
            for(auto &[inst_name, inc] : m_partial)
            {
                if(inc.partial.hostname == r.name && inc.has_srv && inc.has_address)
                    to_check.push_back(inst_name);
            }
            for(const auto &inst_name : to_check)
                check_resolved(inst_name);
        }

        // Also update live services with the same hostname
        for(auto &[inst_name, svc] : m_live_services)
        {
            if(svc.hostname == r.name)
            {
                if(std::ranges::find(svc.ipv4_addresses, r.address_string)
                   == svc.ipv4_addresses.end())
                {
                    svc.ipv4_addresses.push_back(r.address_string);
                    if(m_opts.on_updated)
                        m_opts.on_updated(svc, update_event::added, dns_type::a);
                    update_snapshot();
                }
            }
        }
    }

    /// AAAA record: add IPv6 address to partial/live service.
    void process_aaaa(const record_aaaa &r)
    {
        bool any_updated{false};

        for(auto &[inst_name, inc] : m_partial)
        {
            if(inc.partial.hostname == r.name)
            {
                if(std::ranges::find(inc.partial.ipv6_addresses, r.address_string)
                   == inc.partial.ipv6_addresses.end())
                {
                    inc.partial.ipv6_addresses.push_back(r.address_string);
                    inc.has_address = true;
                    any_updated     = true;
                }
            }
        }

        if(any_updated)
        {
            std::vector<std::string> to_check;
            for(auto &[inst_name, inc] : m_partial)
            {
                if(inc.partial.hostname == r.name && inc.has_srv && inc.has_address)
                    to_check.push_back(inst_name);
            }
            for(const auto &inst_name : to_check)
                check_resolved(inst_name);
        }

        for(auto &[inst_name, svc] : m_live_services)
        {
            if(svc.hostname == r.name)
            {
                if(std::ranges::find(svc.ipv6_addresses, r.address_string)
                   == svc.ipv6_addresses.end())
                {
                    svc.ipv6_addresses.push_back(r.address_string);
                    if(m_opts.on_updated)
                        m_opts.on_updated(svc, update_event::added, dns_type::aaaa);
                    update_snapshot();
                }
            }
        }
    }

    /// TXT record: update TXT entries in partial/live service.
    void process_txt(const record_txt &r)
    {
        // Update partial if present
        if(auto it = m_partial.find(r.name); it != m_partial.end())
        {
            merge_txt(it->second.partial.txt_entries, r.entries);
            return;
        }

        // Update live service
        if(auto it = m_live_services.find(r.name); it != m_live_services.end())
        {
            bool changed = merge_txt(it->second.txt_entries, r.entries);
            if(changed)
            {
                if(m_opts.on_updated)
                    m_opts.on_updated(it->second, update_event::added, dns_type::txt);
                update_snapshot();
            }
        }
    }

    /// Merges src TXT entries into dst (last value wins per key).
    /// Returns true if any entry was added or changed.
    static bool merge_txt(std::vector<service_txt> &dst, const std::vector<service_txt> &src)
    {
        bool changed{false};
        for(const auto &e : src)
        {
            auto it = std::ranges::find_if(dst,
                [&](const service_txt &x) { return x.key == e.key; });
            if(it == dst.end())
            {
                dst.push_back(e);
                changed = true;
            }
            else if(it->value != e.value)
            {
                it->value = e.value;
                changed   = true;
            }
        }
        return changed;
    }

    /// If the named partial instance has both has_srv and has_address, promote
    /// it to m_live_services and fire on_found.
    void check_resolved(const std::string &inst_name)
    {
        auto it = m_partial.find(inst_name);
        if(it == m_partial.end())
            return;

        if(!it->second.has_srv || !it->second.has_address)
            return;

        // Promote to live
        resolved_service svc = std::move(it->second.partial);
        m_partial.erase(it);

        m_live_services.emplace(inst_name, svc);

        if(m_opts.on_found)
            m_opts.on_found(svc);

        update_snapshot();
    }

    /// Called by the cache's on_expired callback when TTL-expired entries are evicted.
    ///
    /// For each expired entry:
    ///   - SRV record: fires on_lost(timeout or goodbye) and removes from live/partial
    ///   - A/AAAA record for a live service: fires on_updated(removed)
    ///   - TXT record for a live service: fires on_updated(removed)
    void handle_expired(std::vector<cache_entry> expired)
    {
        for(const auto &entry : expired)
        {
            std::visit([this, &entry](const auto &r)
            {
                using T = std::remove_cvref_t<decltype(r)>;

                if constexpr (std::is_same_v<T, record_srv>)
                {
                    // SRV expiry -- service is lost
                    auto it = m_live_services.find(r.name);
                    if(it == m_live_services.end())
                    {
                        // May still be partial -- just clean up
                        m_partial.erase(r.name);
                        m_goodbye_instances.erase(r.name);
                        return;
                    }

                    resolved_service last_known = it->second;
                    m_live_services.erase(it);
                    m_partial.erase(r.name);

                    // Determine reason from goodbye side map
                    loss_reason reason = m_goodbye_instances.erase(r.name) > 0
                        ? loss_reason::goodbye
                        : loss_reason::timeout;

                    if(m_opts.on_lost)
                        m_opts.on_lost(last_known, reason);

                    update_snapshot();
                }
                else if constexpr (std::is_same_v<T, record_a>)
                {
                    for(auto &[inst_name, svc] : m_live_services)
                    {
                        if(svc.hostname != r.name)
                            continue;
                        auto it = std::ranges::find(svc.ipv4_addresses, r.address_string);
                        if(it != svc.ipv4_addresses.end())
                        {
                            svc.ipv4_addresses.erase(it);
                            if(m_opts.on_updated)
                                m_opts.on_updated(svc, update_event::removed, dns_type::a);
                            update_snapshot();
                        }
                    }
                }
                else if constexpr (std::is_same_v<T, record_aaaa>)
                {
                    for(auto &[inst_name, svc] : m_live_services)
                    {
                        if(svc.hostname != r.name)
                            continue;
                        auto it = std::ranges::find(svc.ipv6_addresses, r.address_string);
                        if(it != svc.ipv6_addresses.end())
                        {
                            svc.ipv6_addresses.erase(it);
                            if(m_opts.on_updated)
                                m_opts.on_updated(svc, update_event::removed, dns_type::aaaa);
                            update_snapshot();
                        }
                    }
                }
                else if constexpr (std::is_same_v<T, record_txt>)
                {
                    if(auto lit = m_live_services.find(r.name); lit != m_live_services.end())
                    {
                        // TXT expiry: clear txt_entries for entries that were in this record
                        bool changed{false};
                        for(const auto &e : r.entries)
                        {
                            auto eit = std::ranges::find_if(lit->second.txt_entries,
                                [&](const service_txt &x) { return x.key == e.key; });
                            if(eit != lit->second.txt_entries.end())
                            {
                                lit->second.txt_entries.erase(eit);
                                changed = true;
                            }
                        }
                        if(changed)
                        {
                            if(m_opts.on_updated)
                                m_opts.on_updated(lit->second, update_event::removed, dns_type::txt);
                            update_snapshot();
                        }
                    }
                }
                // PTR expiry -- silently ignored (SRV expiry is the loss trigger)
                (void)entry;
            }, entry.record);
        }
    }

    // -------------------------------------------------------------------------
    // Private methods -- watch/unwatch
    // -------------------------------------------------------------------------

    void do_watch(std::string svc_type)
    {
        m_watches.try_emplace(std::move(svc_type));

        // If the monitor is already running, re-arm the scheduler so the new
        // watch type receives its first query at the next scheduled tick.
        if(this->m_loop)
            arm_scheduler();
    }

    void do_unwatch(std::string svc_type)
    {
        if(!m_watches.contains(svc_type))
            return;

        // Fire on_lost(unwatched) for every live service of this type
        std::vector<std::string> to_remove;
        for(const auto &[inst_name, svc] : m_live_services)
        {
            // Determine service type by looking at partial cache or instance name convention
            // The service_type is stored in incomplete_instance for partials.
            // For live services we need to find the PTR association.
            // We use the m_instance_type map populated in process_ptr.
            if(auto tit = m_instance_type.find(inst_name); tit != m_instance_type.end())
            {
                if(tit->second == svc_type)
                    to_remove.push_back(inst_name);
            }
        }

        for(const auto &inst_name : to_remove)
        {
            if(auto it = m_live_services.find(inst_name); it != m_live_services.end())
            {
                if(m_opts.on_lost)
                    m_opts.on_lost(it->second, loss_reason::unwatched);
                m_live_services.erase(it);
            }
        }

        // Remove partial instances of this type
        std::vector<std::string> partial_to_remove;
        for(auto &[inst_name, inc] : m_partial)
        {
            if(inc.service_type == svc_type)
                partial_to_remove.push_back(inst_name);
        }
        for(const auto &inst_name : partial_to_remove)
            m_partial.erase(inst_name);

        // Remove instance type tracking entries and their known hostnames.
        // Hostnames may be shared across service types (same host, different services),
        // so only remove a hostname if no remaining live or partial instance uses it.
        std::vector<std::string> type_to_remove;
        for(auto &[inst_name, svc_t] : m_instance_type)
        {
            if(svc_t == svc_type)
                type_to_remove.push_back(inst_name);
        }
        for(const auto &inst_name : type_to_remove)
            m_instance_type.erase(inst_name);

        // Rebuild m_known_hostnames from remaining live/partial instances
        m_known_hostnames.clear();
        for(const auto &[name, svc] : m_live_services)
        {
            if(!svc.hostname.empty())
                m_known_hostnames.insert(svc.hostname);
        }
        for(const auto &[name, inc] : m_partial)
        {
            if(!inc.partial.hostname.empty())
                m_known_hostnames.insert(inc.partial.hostname);
        }

        m_watches.erase(svc_type);
        m_goodbye_instances.clear(); // clear any goodbye state for this type
        update_snapshot();
    }

    // -------------------------------------------------------------------------
    // Private methods -- scheduler
    // -------------------------------------------------------------------------

    /// Compute the earliest upcoming deadline and arm the scheduler timer.
    ///
    /// The wakeup is the minimum of:
    ///   - The next backoff deadline across all watched types (discover mode)
    ///   - The next TTL-refresh fire_point across all active refresh schedules
    ///     (discover + ttl_refresh modes)
    ///   - now + 1 s as a periodic expiry-sweep floor (all modes)
    ///
    /// Called from async_start(), do_watch() (if already started), and
    /// on_scheduler_tick() to keep the scheduling loop alive.
    void arm_scheduler()
    {
        using namespace std::chrono;
        auto now = Clock::now();

        // Default wakeup: periodic expiry sweep every 1s (observe mode / fallback)
        auto next = now + seconds{1};
        bool has_scheduled_event = false;

        if(m_opts.mode == monitor_mode::discover)
        {
            for(auto &[svc_type, ws] : m_watches)
            {
                // Peek at the interval that will be used on the NEXT tick:
                //   - If never queried (first==true), the next tick fires at initial_interval.
                //   - Otherwise, the interval doubles: min(current * multiplier, max_interval).
                std::chrono::milliseconds interval{};
                if(ws.backoff.first)
                {
                    interval = this->m_mdns_opts.initial_interval;
                }
                else
                {
                    using namespace std::chrono;
                    auto next_fp = static_cast<double>(ws.backoff.current_interval.count())
                                   * this->m_mdns_opts.backoff_multiplier;
                    auto next_ms = duration_cast<milliseconds>(
                        std::chrono::duration<double, std::milli>(next_fp));
                    interval = (next_ms < this->m_mdns_opts.max_interval)
                                   ? next_ms
                                   : this->m_mdns_opts.max_interval;
                }
                auto deadline = now + interval;
                if(!has_scheduled_event || deadline < next)
                {
                    next = deadline;
                    has_scheduled_event = true;
                }
            }
        }

        // TTL refresh schedules: discover + ttl_refresh modes
        if(m_opts.mode == monitor_mode::discover || m_opts.mode == monitor_mode::ttl_refresh)
        {
            for(auto &[key, sched] : m_refresh_schedules)
            {
                if(sched.next_idx < sched.fire_at.size())
                {
                    auto tp = sched.fire_at[sched.next_idx];
                    if(!has_scheduled_event || tp < next)
                    {
                        next = tp;
                        has_scheduled_event = true;
                    }
                }
            }
        }

        // Fall back to 1s expiry sweep if no backoff/refresh events are scheduled
        // (observe mode, or discover/ttl_refresh with no watches or exhausted schedules)
        if(!has_scheduled_event)
            next = now + seconds{1};

        auto delay = duration_cast<milliseconds>(next - now);
        if(delay.count() < 0)
            delay = milliseconds{0};

        m_scheduler_timer.expires_after(delay);

        auto guard = std::weak_ptr<bool>(this->m_alive);
        m_scheduler_timer.async_wait([this, guard](std::error_code ec)
        {
            if(ec || !guard.lock())
                return;
            on_scheduler_tick();
        });
    }

    /// Scheduler tick handler: drives cache expiry, backoff queries, and TTL
    /// refresh queries, then re-arms the timer.
    void on_scheduler_tick()
    {
        if(this->m_stopped.load(std::memory_order_acquire))
            return;

        // Drive loss detection on every tick (all modes)
        m_cache.erase_expired();

        auto now = Clock::now();

        // Backoff queries -- discover mode only
        if(m_opts.mode == monitor_mode::discover)
        {
            for(auto &[svc_type, ws] : m_watches)
            {
                // On first invocation advance_backoff returns initial_interval and
                // clears the first flag.  Subsequent calls double the interval.
                // We send the query unconditionally: the timer was set to fire at
                // the backoff deadline, so it is always time to query when we get here.
                (void)detail::advance_backoff(ws.backoff, this->m_mdns_opts);
                send_ptr_query(svc_type);
            }
        }

        // TTL refresh queries -- discover + ttl_refresh modes
        if(m_opts.mode == monitor_mode::discover || m_opts.mode == monitor_mode::ttl_refresh)
        {
            for(auto &[key, sched] : m_refresh_schedules)
            {
                while(sched.next_idx < sched.fire_at.size()
                      && sched.fire_at[sched.next_idx] <= now)
                {
                    // Extract instance name from key ("{instance_name}:{type}")
                    // and send the appropriate refresh query.
                    auto sep = key.rfind(':');
                    if(sep != std::string::npos)
                    {
                        std::string inst = key.substr(0, sep);
                        send_instance_queries(inst);
                    }
                    ++sched.next_idx;
                }
            }
        }

        // Re-arm for the next tick
        arm_scheduler();
    }

    /// Build or rebuild the TTL refresh schedule for a record identified by
    /// @p key ("{instance_name}:{dns_type_tag}") using @p wire_ttl and the
    /// current insertion time from the clock.
    ///
    /// Called whenever a new or refreshed record is inserted for a live or
    /// partial instance in discover or ttl_refresh mode.
    void rebuild_refresh_schedule(const std::string &key, uint32_t wire_ttl)
    {
        if(m_opts.mode != monitor_mode::discover && m_opts.mode != monitor_mode::ttl_refresh)
            return;

        if(this->m_mdns_opts.ttl_refresh_thresholds.empty())
            return;

        auto inserted_at = Clock::now();
        m_refresh_schedules[key] = detail::make_refresh_schedule<Clock>(
            wire_ttl, this->m_mdns_opts, inserted_at, m_rng);
    }

    // -------------------------------------------------------------------------
    // Private methods -- query sending
    // -------------------------------------------------------------------------

    void send_ptr_query(const std::string &svc_type)
    {
        auto pkt = detail::build_dns_query(svc_type, dns_type::ptr);
        this->m_socket.send(this->multicast_endpoint(),
                            std::span<const std::byte>(pkt));
    }

    /// Send SRV + A + AAAA queries for a specific service instance.
    ///
    /// Per RFC 6762 §5.2, refreshing a service instance requires querying the
    /// SRV record (authoritative) and both address record types to cover dual-
    /// stack hosts.
    void send_instance_queries(const std::string &inst_name)
    {
        auto srv_pkt  = detail::build_dns_query(inst_name, dns_type::srv);
        auto a_pkt    = detail::build_dns_query(inst_name, dns_type::a);
        auto aaaa_pkt = detail::build_dns_query(inst_name, dns_type::aaaa);

        this->m_socket.send(this->multicast_endpoint(),
                            std::span<const std::byte>(srv_pkt));
        this->m_socket.send(this->multicast_endpoint(),
                            std::span<const std::byte>(a_pkt));
        this->m_socket.send(this->multicast_endpoint(),
                            std::span<const std::byte>(aaaa_pkt));
    }

    // -------------------------------------------------------------------------
    // Private methods -- snapshot management
    // -------------------------------------------------------------------------

    void update_snapshot()
    {
        std::vector<resolved_service> snap;
        snap.reserve(m_live_services.size());
        for(const auto &[name, svc] : m_live_services)
        {
            resolved_service entry = svc;

            // Populate TTL fields from the SRV cache entry (MON-05).
            // If the SRV record has already expired (race between erase_expired and
            // update_snapshot), we keep the zeroed defaults from the live entry.
            auto srv_entries = m_cache.find(name, dns_type::srv);
            if(!srv_entries.empty())
            {
                entry.wire_ttl      = srv_entries.front().wire_ttl;
                entry.ttl_remaining = srv_entries.front().ttl_remaining;
            }

            snap.push_back(std::move(entry));
        }

        m_services_snapshot.store(
            std::make_shared<const std::vector<resolved_service>>(std::move(snap)),
            std::memory_order_release);
    }

    // -------------------------------------------------------------------------
    // Data members
    // -------------------------------------------------------------------------

    /// Dedicated scheduler timer for backoff/TTL-refresh scheduling.
    /// Separate from the base recv timer to allow independent scheduling.
    timer_type m_scheduler_timer;

    monitor_options m_opts;

    /// Callback fired when the monitor is fully stopped (via stop()).
    detail::move_only_function<void(std::error_code)> m_on_done;

    /// TTL-aware cache for all received mDNS records.
    record_cache<Clock> m_cache;

    /// Seeded RNG for backoff jitter and probe randomisation.
    std::mt19937 m_rng;

    /// Per-watched-service-type backoff state. Keyed by service type string.
    std::unordered_map<std::string, watched_type_state> m_watches;

    /// Per-record TTL refresh schedules. Keyed by "{instance_name}:{type_tag}"
    /// (e.g., "MyServer._http._tcp.local:srv"). Created/rebuilt on record
    /// insertion for watched instances in discover and ttl_refresh modes.
    std::unordered_map<std::string, detail::ttl_refresh_schedule<Clock>> m_refresh_schedules;

    /// Partial resolution accumulator for instances still awaiting SRV/address.
    std::unordered_map<std::string, incomplete_instance> m_partial;

    /// Fully-resolved services currently considered live.
    std::unordered_map<std::string, resolved_service> m_live_services;

    /// Hostname set for A/AAAA record receive filtering.
    /// Only addresses for known hostnames (from correlated SRV records) are
    /// processed; unrelated A/AAAA traffic is ignored.
    std::unordered_set<std::string> m_known_hostnames;

    /// Maps instance_name -> service_type for un-watch filtering.
    /// Populated in process_ptr() alongside the m_partial entry.
    std::unordered_map<std::string, std::string> m_instance_type;

    /// Set of instance names for which a goodbye SRV (TTL=0) was received.
    /// Used to distinguish loss_reason::goodbye from loss_reason::timeout.
    std::unordered_set<std::string> m_goodbye_instances;

    /// Lock-free snapshot for services(). Updated atomically on the executor
    /// thread after every state change. Readers obtain a reference-counted
    /// view without holding any lock.
    std::atomic<std::shared_ptr<const std::vector<resolved_service>>> m_services_snapshot;
};

}

#endif
