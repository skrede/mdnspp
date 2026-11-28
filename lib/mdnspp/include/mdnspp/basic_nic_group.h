#ifndef HPP_GUARD_MDNSPP_BASIC_NIC_GROUP_H
#define HPP_GUARD_MDNSPP_BASIC_NIC_GROUP_H

#include "mdnspp/policy.h"
#include "mdnspp/ip_address.h"
#include "mdnspp/basic_observer.h"
#include "mdnspp/resolved_service.h"
#include "mdnspp/basic_nic_monitor.h"
#include "mdnspp/network_interface.h"
#include "mdnspp/nic_group_options.h"
#include "mdnspp/basic_service_server.h"
#include "mdnspp/basic_service_monitor.h"

#include "mdnspp/detail/peer_traits.h"
#include "mdnspp/detail/nic_group_slots.h"
#include "mdnspp/detail/sibling_records.h"
#include "mdnspp/detail/nic_family_union.h"
#include "mdnspp/detail/nic_group_family.h"
#include "mdnspp/detail/nic_group_builder.h"
#include "mdnspp/detail/nic_group_collect.h"
#include "mdnspp/detail/interface_addresses.h"

#include <mutex>
#include <atomic>
#include <memory>
#include <string>
#include <vector>
#include <utility>
#include <string_view>
#include <system_error>
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
        , m_siblings(std::make_shared<detail::sibling_records>())
        , m_builder(ex, m_grp_opts, m_siblings, std::move(peer_opts)...)
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
        return detail::collect_services(m_slots, m_grp_opts.dedup);
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
    std::shared_ptr<detail::sibling_records> m_siblings;
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

        m_slots.populate(nic, [&](detail::nic_family_unions &unions)
        {
            bool built = false;
            for(address_family family : detail::address_families)
            {
                if(detail::has_family(nic, family))
                    built = add_family(nic, family, unions) || built;
            }
            return built;
        });
    }

    bool add_family(const network_interface &nic, address_family family, detail::nic_family_unions &unions)
    {
        const auto sock_opts = socket_options_for(nic, family);
        if(!detail::family_matches(sock_opts, family))
        {
            if(m_grp_opts.on_error)
                m_grp_opts.on_error(nic, std::make_error_code(std::errc::invalid_argument), "socket_options_factory");
            return false;
        }
        typename detail::nic_group_slots<P, Peers...>::instance_tuple instances;
        if(!m_builder.build(instances, {nic, family, sock_opts, unions}, m_watch_set))
            return false;
        m_slots.add(nic, family, std::move(instances));
        return true;
    }

    policy_socket_options_t<P> socket_options_for(const network_interface &nic, address_family family)
    {
        if(m_grp_opts.socket_options_factory)
            return m_grp_opts.socket_options_factory(nic, family);
        return detail::default_family_options<policy_socket_options_t<P>>(nic, family);
    }
};

}

#include "mdnspp/detail/dynamic_nic_group.h"

#endif
