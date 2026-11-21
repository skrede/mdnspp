#ifndef HPP_GUARD_MDNSPP_BASIC_NIC_GROUP_H
#define HPP_GUARD_MDNSPP_BASIC_NIC_GROUP_H

#include "mdnspp/policy.h"
#include "mdnspp/basic_observer.h"
#include "mdnspp/resolved_service.h"
#include "mdnspp/basic_nic_monitor.h"
#include "mdnspp/network_interface.h"
#include "mdnspp/nic_group_options.h"
#include "mdnspp/basic_service_server.h"
#include "mdnspp/basic_service_monitor.h"

#include "mdnspp/detail/peer_traits.h"
#include "mdnspp/detail/nic_group_slots.h"
#include "mdnspp/detail/nic_group_builder.h"

#include <mutex>
#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <utility>
#include <string_view>
#include <unordered_set>

namespace mdnspp {

template <policy_like P, template <typename...> class... Peers>
class basic_nic_group
{
public:
    using executor_type = typename P::executor_type;

    basic_nic_group(const basic_nic_group &) = delete;
    basic_nic_group &operator=(const basic_nic_group &) = delete;
    basic_nic_group(basic_nic_group &&) = delete;
    basic_nic_group &operator=(basic_nic_group &&) = delete;

    explicit basic_nic_group(executor_type ex,
                             basic_nic_group_options<P> grp_opts,
                             std::vector<typename detail::peer_traits<Peers, P>::options_type>... peer_opts)
        : m_alive(std::make_shared<bool>(true))
        , m_grp_opts(std::move(grp_opts))
        , m_monitor(ex, std::move(m_grp_opts.monitor_opts))
        , m_stopped(true)
        , m_builder(ex, m_grp_opts, std::move(peer_opts)...)
    {
    }

    ~basic_nic_group()
    {
        stop();
    }

    void start()
    {
        if(!m_stopped.exchange(false, std::memory_order_acq_rel))
            return;

        watch_nic_changes(std::weak_ptr<bool>(m_alive));
        m_monitor.start();

        std::lock_guard lock(m_mutex);
        for(const auto &nic : m_monitor.current())
            on_nic_added(nic);
    }

    void stop()
    {
        if(m_stopped.exchange(true, std::memory_order_acq_rel))
            return;

        m_monitor.stop();

        {
            std::lock_guard lock(m_mutex);
            m_slots.stop_all();
            m_slots.clear();
        }

        m_alive.reset();
        m_alive = std::make_shared<bool>(true);
    }

    std::vector<resolved_service> services() const
        requires ((detail::peer_traits<Peers, P>::provides_services || ...))
    {
        std::lock_guard lock(m_mutex);
        if(m_grp_opts.dedup == dedup_mode::per_interface)
            return m_slots.collect_per_interface();
        return m_slots.collect_merged();
    }

    void watch(std::string_view service_type)
        requires ((detail::peer_traits<Peers, P>::provides_services || ...))
    {
        std::lock_guard lock(m_mutex);
        m_watch_set.emplace(service_type);
        m_slots.for_each_monitor([service_type](auto &inst)
        {
            inst.watch(service_type);
        });
    }

    void unwatch(std::string_view service_type)
        requires ((detail::peer_traits<Peers, P>::provides_services || ...))
    {
        std::lock_guard lock(m_mutex);
        m_watch_set.erase(std::string(service_type));
        m_slots.for_each_monitor([service_type](auto &inst)
        {
            inst.unwatch(service_type);
        });
    }

private:
    std::shared_ptr<bool> m_alive;
    basic_nic_group_options<P> m_grp_opts;
    basic_nic_monitor<P> m_monitor;
    std::atomic<bool> m_stopped;
    detail::nic_group_builder<P, Peers...> m_builder;
    detail::nic_group_slots<P, Peers...> m_slots;
    std::unordered_set<std::string> m_watch_set;
    mutable std::mutex m_mutex;

    void watch_nic_changes(std::weak_ptr<bool> weak)
    {
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
            m_slots.remove(nic.index);
        });
    }

    void on_nic_added(const network_interface &nic)
    {
        if(m_slots.contains(nic.index))
            return;
        if(m_grp_opts.interface_filter && !m_grp_opts.interface_filter(nic))
            return;

        const auto sock_opts = socket_options_for(nic);
        m_builder.build(m_slots.add(nic), nic, sock_opts, m_watch_set);
    }

    policy_socket_options_t<P> socket_options_for(const network_interface &nic)
    {
        if(m_grp_opts.socket_options_factory)
            return m_grp_opts.socket_options_factory(nic);

        policy_socket_options_t<P> sock_opts{};
        if(!nic.ipv4_address.empty())
            sock_opts.interface_address = nic.ipv4_address;
        else if(!nic.ipv6_address.empty())
            sock_opts.interface_address = nic.ipv6_address;
        return sock_opts;
    }
};

}

#include "mdnspp/detail/dynamic_nic_group.h"

#endif
