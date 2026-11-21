#ifndef HPP_GUARD_MDNSPP_DETAIL_DYNAMIC_NIC_GROUP_H
#define HPP_GUARD_MDNSPP_DETAIL_DYNAMIC_NIC_GROUP_H

#include "mdnspp/detail/peer_traits.h"
#include "mdnspp/detail/nic_group_model.h"

#include "mdnspp/policy.h"
#include "mdnspp/basic_observer.h"
#include "mdnspp/basic_nic_group.h"
#include "mdnspp/monitor_options.h"
#include "mdnspp/observer_options.h"
#include "mdnspp/resolved_service.h"
#include "mdnspp/nic_group_options.h"
#include "mdnspp/basic_service_server.h"
#include "mdnspp/basic_service_monitor.h"

#include <memory>
#include <vector>
#include <utility>
#include <optional>
#include <string_view>
#include <system_error>

namespace mdnspp {

template <policy_like P>
class basic_dynamic_nic_group
{
public:
    using executor_type = typename P::executor_type;

    basic_dynamic_nic_group(const basic_dynamic_nic_group &) = delete;
    basic_dynamic_nic_group &operator=(const basic_dynamic_nic_group &) = delete;
    basic_dynamic_nic_group(basic_dynamic_nic_group &&) = delete;
    basic_dynamic_nic_group &operator=(basic_dynamic_nic_group &&) = delete;

    explicit basic_dynamic_nic_group(executor_type ex, basic_nic_group_options<P> opts = {})
        : m_executor(ex)
        , m_grp_opts(std::move(opts))
    {
    }

    void monitor(std::vector<monitor_options> opts)
    {
        for(const auto &o : opts)
        {
            if(auto ec = detail::validate_nic_group_peer_options(o))
                throw std::system_error(ec,
                    "basic_dynamic_nic_group::monitor: per-NIC monitor_options must not carry "
                    "callbacks; use the interface-stamped callbacks in basic_nic_group_options");
        }
        m_monitor_opts = std::move(opts);
    }

    void announce(std::vector<server_peer_options> opts)
    {
        m_server_opts = std::move(opts);
    }

    void observe(std::vector<observer_options> opts)
    {
        for(const auto &o : opts)
        {
            if(auto ec = detail::validate_nic_group_peer_options(o))
                throw std::system_error(ec,
                    "basic_dynamic_nic_group::observe: per-NIC observer_options must not carry "
                    "callbacks; use the interface-stamped callbacks in basic_nic_group_options");
        }
        m_observer_opts = std::move(opts);
    }

    void start()
    {
        if(!m_impl)
            make_group();
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
    basic_nic_group_options<P> m_grp_opts;
    std::unique_ptr<detail::nic_group_concept> m_impl;
    std::optional<std::vector<monitor_options>> m_monitor_opts;
    std::optional<std::vector<server_peer_options>> m_server_opts;
    std::optional<std::vector<observer_options>> m_observer_opts;

    void make_group()
    {
        if(m_monitor_opts)
            make_monitor_group(std::move(*m_monitor_opts));
        else if(m_server_opts && m_observer_opts)
            make_model<basic_service_server, basic_observer>(std::move(*m_server_opts), std::move(*m_observer_opts));
        else if(m_server_opts)
            make_model<basic_service_server>(std::move(*m_server_opts));
        else if(m_observer_opts)
            make_model<basic_observer>(std::move(*m_observer_opts));
    }

    void make_monitor_group(std::vector<monitor_options> &&mon)
    {
        if(m_server_opts && m_observer_opts)
            make_model<basic_service_monitor, basic_service_server, basic_observer>(
                std::move(mon), std::move(*m_server_opts), std::move(*m_observer_opts));
        else if(m_server_opts)
            make_model<basic_service_monitor, basic_service_server>(std::move(mon), std::move(*m_server_opts));
        else if(m_observer_opts)
            make_model<basic_service_monitor, basic_observer>(std::move(mon), std::move(*m_observer_opts));
        else
            make_model<basic_service_monitor>(std::move(mon));
    }

    template <template <typename...> class... Peers, typename... Options>
    void make_model(Options &&...peer_opts)
    {
        m_impl = std::make_unique<detail::nic_group_model<basic_nic_group<P, Peers...>>>(
            m_executor, std::move(m_grp_opts), std::forward<Options>(peer_opts)...);
    }
};

}

#endif
