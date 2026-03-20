#ifndef HPP_GUARD_MDNSPP_BASIC_NIC_GROUP_H
#define HPP_GUARD_MDNSPP_BASIC_NIC_GROUP_H

#include "mdnspp/policy.h"
#include "mdnspp/basic_observer.h"
#include "mdnspp/nic_group_options.h"
#include "mdnspp/basic_nic_monitor.h"
#include "mdnspp/resolved_service.h"
#include "mdnspp/basic_service_server.h"
#include "mdnspp/basic_service_monitor.h"

#include "mdnspp/detail/peer_traits.h"

#include <mutex>
#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <optional>
#include <utility>
#include <string_view>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>

namespace mdnspp {

// basic_nic_group<P, Peers...> — variadic multi-NIC orchestrator.
//
// Owns a basic_nic_monitor and automatically creates/destroys per-NIC instances
// of each Peer type when network interfaces are added or removed.
//
// Template parameters:
//   P       — Policy (executor, socket, timer types)
//   Peers   — Template templates: basic_service_monitor, basic_service_server,
//              and/or basic_observer in any combination.
//
// Lifecycle:
//   1. Construct with (ex, grp_opts, peer_opts_vec...) — one options vector per Peer type.
//   2. start() — registers NIC callbacks, starts the monitor, creates initial instances.
//   3. stop()  — stops all peer instances, stops the monitor.
//
// Conditional API (via requires):
//   services()  — available when basic_service_monitor is in the Peers pack.
//   watch()     — available when basic_service_monitor is in the Peers pack.
//   unwatch()   — available when basic_service_monitor is in the Peers pack.
//
// Thread safety:
//   start(), stop(), services(), watch(), and unwatch() may be called from
//   any thread. m_mutex protects m_instances and m_watch_set.

template <Policy P, template <typename> class... Peers>
class basic_nic_group
{
public:
    using executor_type = typename P::executor_type;

    basic_nic_group(const basic_nic_group &) = delete;
    basic_nic_group &operator=(const basic_nic_group &) = delete;
    basic_nic_group(basic_nic_group &&) = delete;
    basic_nic_group &operator=(basic_nic_group &&) = delete;

    /// Construct the group.
    ///
    /// @param ex         Executor for all async operations.
    /// @param grp_opts   Group-level options (dedup mode, interface filter, socket factory).
    /// @param peer_opts  Per-peer-type options vectors (one argument per Peer in the pack).
    explicit basic_nic_group(executor_type ex,
                             nic_group_options grp_opts,
                             std::vector<typename peer_traits<Peers, P>::options_type>... peer_opts)
        : m_executor(ex)
        , m_grp_opts(std::move(grp_opts))
        , m_monitor(ex, m_grp_opts.monitor_opts)
        , m_peer_opts(std::move(peer_opts)...)
    {
    }

    ~basic_nic_group()
    {
        stop();
    }

    /// Begin NIC monitoring and create initial per-NIC peer instances.
    void start()
    {
        m_stopped.store(false, std::memory_order_release);

        auto weak = std::weak_ptr<bool>(m_alive);

        m_monitor.on_added([this, weak](const network_interface &nic)
        {
            if(weak.expired()) return;
            std::lock_guard lock(m_mutex);
            on_nic_added(nic);
        });

        m_monitor.on_removed([this, weak](const network_interface &nic)
        {
            if(weak.expired()) return;
            std::lock_guard lock(m_mutex);
            on_nic_removed(nic);
        });

        m_monitor.start();

        // Seed with currently-known interfaces.
        {
            std::lock_guard lock(m_mutex);
            for(const auto &nic : m_monitor.current())
                on_nic_added(nic);
        }
    }

    /// Stop all peer instances and the NIC monitor. Idempotent.
    void stop()
    {
        if(m_stopped.exchange(true, std::memory_order_acq_rel))
            return;

        m_monitor.stop();

        {
            std::lock_guard lock(m_mutex);
            stop_all_instances();
            m_instances.clear();
        }

        m_alive.reset();
        m_alive = std::make_shared<bool>(true);
    }

    // -------------------------------------------------------------------------
    // Conditional API — services() / watch() / unwatch()
    // -------------------------------------------------------------------------

    /// Return a snapshot of all known services across all monitored NICs.
    ///
    /// In merged mode (default): one entry per instance_name (last-seen wins for
    /// source_interface). In per_interface mode: all services from all NICs.
    ///
    /// Only available when basic_service_monitor is in the Peers pack.
    std::vector<resolved_service> services() const
        requires ((peer_traits<Peers, P>::provides_services || ...))
    {
        std::lock_guard lock(m_mutex);
        if(m_grp_opts.dedup == dedup_mode::per_interface)
            return collect_per_interface();
        return collect_merged();
    }

    /// Register interest in a service type across all current and future NICs.
    ///
    /// Only available when basic_service_monitor is in the Peers pack.
    void watch(std::string_view service_type)
        requires ((peer_traits<Peers, P>::provides_services || ...))
    {
        std::lock_guard lock(m_mutex);
        m_watch_set.emplace(service_type);
        for_each_monitor_instance([service_type](auto &inst)
        {
            inst.watch(service_type);
        });
    }

    /// Deregister interest in a service type across all current and future NICs.
    ///
    /// Only available when basic_service_monitor is in the Peers pack.
    void unwatch(std::string_view service_type)
        requires ((peer_traits<Peers, P>::provides_services || ...))
    {
        std::lock_guard lock(m_mutex);
        m_watch_set.erase(std::string(service_type));
        for_each_monitor_instance([service_type](auto &inst)
        {
            inst.unwatch(service_type);
        });
    }

private:
    // -------------------------------------------------------------------------
    // Type index helper
    // -------------------------------------------------------------------------

    // Find the 0-based index of PeerTemplate in Peers...
    template <template <typename> class PeerTemplate,
              template <typename> class Head,
              template <typename> class... Tail>
    static constexpr std::size_t peer_index_of_impl(std::size_t current)
    {
        if constexpr(std::is_same_v<PeerTemplate<P>, Head<P>>)
            return current;
        else if constexpr(sizeof...(Tail) == 0)
            return std::size_t(-1); // not found
        else
            return peer_index_of_impl<PeerTemplate, Tail...>(current + 1);
    }

    template <template <typename> class PeerTemplate>
    static constexpr std::size_t peer_index_of()
    {
        return peer_index_of_impl<PeerTemplate, Peers...>(0);
    }

    // -------------------------------------------------------------------------
    // Per-instance storage type
    // -------------------------------------------------------------------------

    // For each NIC: a tuple of vectors of unique_ptrs, one vector per Peer type.
    using instance_tuple = std::tuple<std::vector<std::unique_ptr<Peers<P>>>...>;

    // -------------------------------------------------------------------------
    // NIC event handlers (called under m_mutex)
    // -------------------------------------------------------------------------

    void on_nic_added(const network_interface &nic)
    {
        if(m_instances.contains(nic.index))
            return; // already present

        if(m_grp_opts.interface_filter && !m_grp_opts.interface_filter(nic))
            return; // filtered out

        // Determine socket_options for this interface.
        socket_options sock_opts;
        if(m_grp_opts.socket_options_factory)
        {
            sock_opts = m_grp_opts.socket_options_factory(nic);
        }
        else
        {
            if(!nic.ipv4_address.empty())
                sock_opts.interface_address = nic.ipv4_address;
            else if(!nic.ipv6_address.empty())
                sock_opts.interface_address = nic.ipv6_address;
        }

        auto &slot = m_instances[nic.index];
        create_instances_for_nic(slot, sock_opts, std::make_index_sequence<sizeof...(Peers)>{});
    }

    void on_nic_removed(const network_interface &nic)
    {
        auto it = m_instances.find(nic.index);
        if(it == m_instances.end())
            return;

        stop_instance_tuple(it->second, std::make_index_sequence<sizeof...(Peers)>{});
        m_instances.erase(it);
    }

    // -------------------------------------------------------------------------
    // Instance creation helpers
    // -------------------------------------------------------------------------

    template <std::size_t... Is>
    void create_instances_for_nic(instance_tuple &slot,
                                  const socket_options &sock_opts,
                                  std::index_sequence<Is...>)
    {
        (create_peer_instances<Is>(slot, sock_opts), ...);
    }

    template <std::size_t I>
    void create_peer_instances(instance_tuple &slot, const socket_options &sock_opts)
    {
        using PeerType = std::tuple_element_t<I, std::tuple<Peers<P>...>>;
        // Extract the template template parameter at position I.
        auto &peer_opts_vec = std::get<I>(m_peer_opts);
        auto &instances_vec = std::get<I>(slot);

        for(const auto &opts : peer_opts_vec)
        {
            auto inst = make_peer_instance<PeerType>(opts, sock_opts);
            start_peer_instance(*inst);
            instances_vec.push_back(std::move(inst));
        }
    }

    // Factory: construct the right peer type from its options.
    template <typename PeerType, typename Options>
    std::unique_ptr<PeerType> make_peer_instance(const Options &opts,
                                                  const socket_options &sock_opts)
    {
        if constexpr(std::is_same_v<PeerType, basic_service_monitor<P>>)
        {
            return std::make_unique<basic_service_monitor<P>>(
                m_executor, opts, sock_opts, m_grp_opts.mdns_opts);
        }
        else if constexpr(std::is_same_v<PeerType, basic_service_server<P>>)
        {
            // opts is server_peer_options {service_info, service_options}
            return std::make_unique<basic_service_server<P>>(
                m_executor, opts.info, opts.opts, sock_opts);
        }
        else if constexpr(std::is_same_v<PeerType, basic_observer<P>>)
        {
            return std::make_unique<basic_observer<P>>(
                m_executor, opts, sock_opts, m_grp_opts.mdns_opts);
        }
        else
        {
            static_assert(sizeof(PeerType) == 0, "Unsupported peer type in basic_nic_group");
        }
    }

    // Start a newly-constructed peer instance and apply any accumulated watches.
    template <typename PeerType>
    void start_peer_instance(PeerType &inst)
    {
        if constexpr(std::is_same_v<PeerType, basic_service_monitor<P>>)
        {
            for(const auto &svc_type : m_watch_set)
                inst.watch(svc_type);
            inst.async_start();
        }
        else if constexpr(std::is_same_v<PeerType, basic_service_server<P>>)
        {
            inst.async_start();
        }
        else if constexpr(std::is_same_v<PeerType, basic_observer<P>>)
        {
            inst.async_observe();
        }
    }

    // -------------------------------------------------------------------------
    // Stop helpers
    // -------------------------------------------------------------------------

    void stop_all_instances()
    {
        for(auto &[idx, slot] : m_instances)
            stop_instance_tuple(slot, std::make_index_sequence<sizeof...(Peers)>{});
    }

    template <std::size_t... Is>
    void stop_instance_tuple(instance_tuple &slot, std::index_sequence<Is...>)
    {
        (stop_peer_instances(std::get<Is>(slot)), ...);
    }

    template <typename PeerType>
    void stop_peer_instances(std::vector<std::unique_ptr<PeerType>> &vec)
    {
        for(auto &inst : vec)
        {
            if(inst)
                inst->stop();
        }
        vec.clear();
    }

    // -------------------------------------------------------------------------
    // Service collection helpers
    // -------------------------------------------------------------------------

    std::vector<resolved_service> collect_merged() const
    {
        std::unordered_map<std::string, resolved_service> by_name;

        for_each_monitor_instance_const([&by_name](const auto &inst)
        {
            for(auto svc : inst.services())
            {
                auto key = svc.instance_name.str();
                by_name[key] = std::move(svc);
            }
        });

        std::vector<resolved_service> result;
        result.reserve(by_name.size());
        for(auto &[k, v] : by_name)
            result.push_back(std::move(v));
        return result;
    }

    std::vector<resolved_service> collect_per_interface() const
    {
        std::vector<resolved_service> result;

        for_each_monitor_instance_const([&result](const auto &inst)
        {
            auto svcs = inst.services();
            result.insert(result.end(),
                          std::make_move_iterator(svcs.begin()),
                          std::make_move_iterator(svcs.end()));
        });

        return result;
    }

    // -------------------------------------------------------------------------
    // Iteration helpers
    // -------------------------------------------------------------------------

    // Call fn(monitor_instance) for every basic_service_monitor instance across all NICs.
    // Requires basic_service_monitor to be in the Peers pack.
    template <typename Fn>
    void for_each_monitor_instance(Fn &&fn)
    {
        constexpr std::size_t idx = peer_index_of<basic_service_monitor>();
        if constexpr(idx != std::size_t(-1))
        {
            for(auto &[nic_idx, slot] : m_instances)
            {
                for(auto &inst_ptr : std::get<idx>(slot))
                {
                    if(inst_ptr)
                        fn(*inst_ptr);
                }
            }
        }
    }

    template <typename Fn>
    void for_each_monitor_instance_const(Fn &&fn) const
    {
        constexpr std::size_t idx = peer_index_of<basic_service_monitor>();
        if constexpr(idx != std::size_t(-1))
        {
            for(const auto &[nic_idx, slot] : m_instances)
            {
                for(const auto &inst_ptr : std::get<idx>(slot))
                {
                    if(inst_ptr)
                        fn(*inst_ptr);
                }
            }
        }
    }

    // -------------------------------------------------------------------------
    // Data members
    // -------------------------------------------------------------------------

    std::shared_ptr<bool> m_alive{std::make_shared<bool>(true)};
    executor_type m_executor;
    nic_group_options m_grp_opts;
    basic_nic_monitor<P> m_monitor;
    std::atomic<bool> m_stopped{true};

    std::tuple<std::vector<typename peer_traits<Peers, P>::options_type>...> m_peer_opts;

    // Keyed by interface index — unique_ptr because basic_* types are non-movable post-start.
    std::unordered_map<unsigned int, instance_tuple> m_instances;

    // Accumulated watch() calls; propagated to new monitor instances on NIC add.
    std::unordered_set<std::string> m_watch_set;

    mutable std::mutex m_mutex;
};

// -------------------------------------------------------------------------
// Type erasure internals
// -------------------------------------------------------------------------

namespace detail {

struct nic_group_concept
{
    virtual ~nic_group_concept() = default;
    virtual void start() = 0;
    virtual void stop() = 0;
    virtual std::vector<resolved_service> services() const = 0;
    virtual void watch(std::string_view service_type) = 0;
    virtual void unwatch(std::string_view service_type) = 0;
};

template <typename Concrete>
struct nic_group_model final : nic_group_concept
{
    template <typename... Args>
    explicit nic_group_model(Args &&...args)
        : m_impl(std::forward<Args>(args)...)
    {
    }

    void start() override { m_impl.start(); }
    void stop() override { m_impl.stop(); }

    std::vector<resolved_service> services() const override
    {
        if constexpr(requires { m_impl.services(); })
            return m_impl.services();
        else
            return {};
    }

    void watch(std::string_view service_type) override
    {
        if constexpr(requires { m_impl.watch(service_type); })
            m_impl.watch(service_type);
    }

    void unwatch(std::string_view service_type) override
    {
        if constexpr(requires { m_impl.unwatch(service_type); })
            m_impl.unwatch(service_type);
    }

    Concrete m_impl;
};

} // namespace detail

// -------------------------------------------------------------------------
// dynamic_nic_group<P> — runtime peer composition via builder pattern
// -------------------------------------------------------------------------

// dynamic_nic_group<P> — type-erased wrapper that selects the correct
// basic_nic_group instantiation at start() time based on which builder
// methods (monitor/announce/observe) were called.
//
// Usage:
//   dynamic_nic_group<DefaultPolicy> grp{ctx.get_executor()};
//   grp.monitor({monitor_options{...}});
//   grp.announce({server_peer_options{info, opts}});
//   grp.start();
//   grp.watch("_http._tcp.local");

template <Policy P>
class dynamic_nic_group
{
public:
    using executor_type = typename P::executor_type;

    dynamic_nic_group(const dynamic_nic_group &) = delete;
    dynamic_nic_group &operator=(const dynamic_nic_group &) = delete;
    dynamic_nic_group(dynamic_nic_group &&) = delete;
    dynamic_nic_group &operator=(dynamic_nic_group &&) = delete;

    explicit dynamic_nic_group(executor_type ex, nic_group_options opts = {})
        : m_executor(ex)
        , m_grp_opts(std::move(opts))
    {
    }

    // -------------------------------------------------------------------------
    // Builder methods — call before start()
    // -------------------------------------------------------------------------

    /// Add service monitor peer (basic_service_monitor).
    void monitor(std::vector<monitor_options> opts)
    {
        m_monitor_opts = std::move(opts);
    }

    /// Add service server peer (basic_service_server).
    void announce(std::vector<server_peer_options> opts)
    {
        m_server_opts = std::move(opts);
    }

    /// Add observer peer (basic_observer).
    void observe(std::vector<observer_options> opts)
    {
        m_observer_opts = std::move(opts);
    }

    // -------------------------------------------------------------------------
    // Lifecycle
    // -------------------------------------------------------------------------

    /// Construct the appropriate basic_nic_group instantiation and start it.
    void start()
    {
        const bool has_monitor  = m_monitor_opts.has_value();
        const bool has_server   = m_server_opts.has_value();
        const bool has_observer = m_observer_opts.has_value();

        if(has_monitor && has_server && has_observer)
        {
            m_impl = std::make_unique<detail::nic_group_model<
                basic_nic_group<P, basic_service_monitor, basic_service_server, basic_observer>>>(
                m_executor, std::move(m_grp_opts),
                std::move(*m_monitor_opts),
                std::move(*m_server_opts),
                std::move(*m_observer_opts));
        }
        else if(has_monitor && has_server)
        {
            m_impl = std::make_unique<detail::nic_group_model<
                basic_nic_group<P, basic_service_monitor, basic_service_server>>>(
                m_executor, std::move(m_grp_opts),
                std::move(*m_monitor_opts),
                std::move(*m_server_opts));
        }
        else if(has_monitor && has_observer)
        {
            m_impl = std::make_unique<detail::nic_group_model<
                basic_nic_group<P, basic_service_monitor, basic_observer>>>(
                m_executor, std::move(m_grp_opts),
                std::move(*m_monitor_opts),
                std::move(*m_observer_opts));
        }
        else if(has_server && has_observer)
        {
            m_impl = std::make_unique<detail::nic_group_model<
                basic_nic_group<P, basic_service_server, basic_observer>>>(
                m_executor, std::move(m_grp_opts),
                std::move(*m_server_opts),
                std::move(*m_observer_opts));
        }
        else if(has_monitor)
        {
            m_impl = std::make_unique<detail::nic_group_model<
                basic_nic_group<P, basic_service_monitor>>>(
                m_executor, std::move(m_grp_opts),
                std::move(*m_monitor_opts));
        }
        else if(has_server)
        {
            m_impl = std::make_unique<detail::nic_group_model<
                basic_nic_group<P, basic_service_server>>>(
                m_executor, std::move(m_grp_opts),
                std::move(*m_server_opts));
        }
        else if(has_observer)
        {
            m_impl = std::make_unique<detail::nic_group_model<
                basic_nic_group<P, basic_observer>>>(
                m_executor, std::move(m_grp_opts),
                std::move(*m_observer_opts));
        }

        if(m_impl)
            m_impl->start();
    }

    void stop()
    {
        if(m_impl)
            m_impl->stop();
    }

    std::vector<resolved_service> services() const
    {
        if(m_impl)
            return m_impl->services();
        return {};
    }

    void watch(std::string_view service_type)
    {
        if(m_impl)
            m_impl->watch(service_type);
    }

    void unwatch(std::string_view service_type)
    {
        if(m_impl)
            m_impl->unwatch(service_type);
    }

private:
    executor_type m_executor;
    nic_group_options m_grp_opts;
    std::unique_ptr<detail::nic_group_concept> m_impl;

    std::optional<std::vector<monitor_options>> m_monitor_opts;
    std::optional<std::vector<server_peer_options>> m_server_opts;
    std::optional<std::vector<observer_options>> m_observer_opts;
};

}

#endif
