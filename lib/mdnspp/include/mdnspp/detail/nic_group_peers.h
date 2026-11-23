#ifndef HPP_GUARD_MDNSPP_DETAIL_NIC_GROUP_PEERS_H
#define HPP_GUARD_MDNSPP_DETAIL_NIC_GROUP_PEERS_H

#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/peer_traits.h"
#include "mdnspp/detail/sibling_records.h"
#include "mdnspp/detail/interface_resolve.h"
#include "mdnspp/detail/advertised_addresses.h"
#include "mdnspp/detail/nic_group_server_callbacks.h"

#include "mdnspp/policy.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/service_info.h"
#include "mdnspp/cache_options.h"
#include "mdnspp/basic_observer.h"
#include "mdnspp/callback_types.h"
#include "mdnspp/monitor_options.h"
#include "mdnspp/service_options.h"
#include "mdnspp/observer_options.h"
#include "mdnspp/resolved_service.h"
#include "mdnspp/network_interface.h"
#include "mdnspp/nic_group_options.h"
#include "mdnspp/basic_service_server.h"
#include "mdnspp/basic_service_monitor.h"

#include <memory>
#include <string>
#include <cstddef>
#include <utility>
#include <string_view>
#include <system_error>
#include <unordered_set>

namespace mdnspp::detail {

template <typename Options>
void reject_peer_callbacks(const Options &opts)
{
    if(auto ec = validate_nic_group_peer_options(opts))
        throw std::system_error(ec,
            "basic_nic_group: per-NIC peer options must not carry callbacks; "
            "use the interface-stamped callbacks in basic_nic_group_options");
}

// The forwarding lambdas capture the group options by reference and the interface by value. They live inside the
// per-NIC instances, which the group destroys before its options, so the captures cannot dangle.
template <policy_like P>
class nic_peer_factory
{
public:
    using executor_type = typename P::executor_type;
    using socket_options_type = policy_socket_options_t<P>;

    nic_peer_factory(executor_type ex, basic_nic_group_options<P> &grp_opts, std::shared_ptr<sibling_records> siblings)
        : m_executor(ex)
        , m_grp_opts(grp_opts)
        , m_siblings(std::move(siblings))
    {
    }

    std::unique_ptr<basic_service_monitor<P>> make(const monitor_options &opts, const network_interface &nic,
                                                   const socket_options_type &sock_opts)
    {
        monitor_options cloned{.mode = opts.mode};
        forward_monitor_events(cloned, nic);
        if(m_grp_opts.on_error)
            cloned.on_error = stamped_error(nic);
        std::error_code ec;
        auto peer = std::make_unique<basic_service_monitor<P>>(m_executor, std::move(cloned), sock_opts,
                                                               m_grp_opts.mdns_opts, cache_options{}, ec);
        return checked(std::move(peer), ec, nic, "service_monitor construction");
    }

    std::unique_ptr<basic_service_server<P>> make(const server_peer_options &opts,
                                                  const std::shared_ptr<shared_server_callbacks> &cbs,
                                                  std::size_t element, const network_interface &nic,
                                                  const socket_options_type &sock_opts)
    {
        service_options cloned = clone_service_options(opts.service);
        forward_shared_callbacks(cloned, cbs);
        if(!cbs->on_error && m_grp_opts.on_error)
            cloned.on_error = stamped_error(nic);
        std::error_code ec;
        auto peer = std::make_unique<basic_service_server<P>>(m_executor, info_on(nic, opts.info), std::move(cloned),
                                                              sock_opts, m_grp_opts.mdns_opts, m_siblings, element, ec);
        return checked(std::move(peer), ec, nic, "service_server construction");
    }

    std::unique_ptr<basic_observer<P>> make(const observer_options &, const network_interface &nic,
                                            const socket_options_type &sock_opts)
    {
        observer_options cloned{};
        if(m_grp_opts.on_record)
            cloned.on_record = [&grp = m_grp_opts, nic](const endpoint &sender, const mdns_record_variant &record)
            {
                grp.on_record(nic, sender, record);
            };
        if(m_grp_opts.on_error)
            cloned.on_error = stamped_error(nic);
        std::error_code ec;
        auto peer = std::make_unique<basic_observer<P>>(m_executor, std::move(cloned), sock_opts,
                                                        m_grp_opts.mdns_opts, ec);
        return checked(std::move(peer), ec, nic, "observer construction");
    }

private:
    executor_type m_executor;
    basic_nic_group_options<P> &m_grp_opts;
    std::shared_ptr<sibling_records> m_siblings;

    template <typename Peer>
    std::unique_ptr<Peer> checked(std::unique_ptr<Peer> peer, std::error_code ec, const network_interface &nic,
                                  std::string_view context)
    {
        if(!ec)
            return peer;
        if(m_grp_opts.on_error)
            m_grp_opts.on_error(nic, ec, context);
        return nullptr;
    }

    // RFC 6762 section 6.2: an instance advertises the addresses of the NIC it runs on, which a user enumerator
    // may describe differently from the host's interface table.
    static service_info info_on(const network_interface &nic, service_info info)
    {
        resolve_advertised_addresses(interface_binding{}, announcing_link{&nic, true}, info);
        info.auto_address = false;
        return info;
    }

    error_handler stamped_error(const network_interface &nic)
    {
        return [&grp = m_grp_opts, nic](std::error_code ec, std::string_view context)
        {
            grp.on_error(nic, ec, context);
        };
    }

    void forward_monitor_events(monitor_options &cloned, const network_interface &nic)
    {
        if(m_grp_opts.on_found)
            cloned.on_found = [&grp = m_grp_opts, nic](const resolved_service &svc)
            {
                grp.on_found(nic, svc);
            };
        if(m_grp_opts.on_updated)
            cloned.on_updated = [&grp = m_grp_opts, nic](const resolved_service &svc, update_event event, dns_type type)
            {
                grp.on_updated(nic, svc, event, type);
            };
        if(m_grp_opts.on_lost)
            cloned.on_lost = [&grp = m_grp_opts, nic](const resolved_service &svc, loss_reason reason)
            {
                grp.on_lost(nic, svc, reason);
            };
    }
};

template <policy_like P>
void start_peer(basic_service_monitor<P> &inst, const std::unordered_set<std::string> &watches)
{
    for(const auto &svc_type : watches)
        inst.watch(svc_type);
    inst.async_start();
}

template <policy_like P>
void start_peer(basic_service_server<P> &inst, const std::unordered_set<std::string> &)
{
    inst.async_start();
}

template <policy_like P>
void start_peer(basic_observer<P> &inst, const std::unordered_set<std::string> &)
{
    inst.async_observe();
}

}

#endif
