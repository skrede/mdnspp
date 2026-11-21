#ifndef HPP_GUARD_MDNSPP_DETAIL_MONITOR_LOSS_H
#define HPP_GUARD_MDNSPP_DETAIL_MONITOR_LOSS_H

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/monitor_instances.h"

#include "mdnspp/records.h"
#include "mdnspp/dns_name.h"
#include "mdnspp/cache_entry.h"
#include "mdnspp/monitor_options.h"
#include "mdnspp/resolved_service.h"

#include <string>
#include <vector>
#include <utility>
#include <variant>
#include <algorithm>
#include <type_traits>

namespace mdnspp::detail {

// Removes what expired from the cache or belongs to an unwatched type, and reports on_lost and
// on_updated. forget_cb receives every instance whose SRV refresh schedule must go.
class monitor_loss
{
public:
    using changed_callback = move_only_function<void()>;
    using forget_callback = move_only_function<void(const dns_name &)>;

    monitor_loss(monitor_instances &instances, monitor_options &opts, changed_callback changed_cb,
                 forget_callback forget_cb)
        : m_opts(opts)
        , m_changed_cb(std::move(changed_cb))
        , m_forget_cb(std::move(forget_cb))
        , m_instances(instances)
    {
    }

    // PTR expiry is ignored: SRV expiry is the loss trigger.
    void expire(std::vector<cache_entry> expired)
    {
        for(const auto &entry : expired)
        {
            std::visit([this](const auto &r)
            {
                using T = std::remove_cvref_t<decltype(r)>;

                if constexpr (std::is_same_v<T, record_srv>)
                    expire_srv(r);
                else if constexpr (std::is_same_v<T, record_a>)
                    expire_address(r.name, r.address_string, dns_type::a);
                else if constexpr (std::is_same_v<T, record_aaaa>)
                    expire_address(r.name, r.address_string, dns_type::aaaa);
                else if constexpr (std::is_same_v<T, record_txt>)
                    expire_txt(r);
            }, entry.record);
        }
    }

    // The caller publishes the change once afterwards.
    void drop_type(const dns_name &type)
    {
        drop_live_of(type);
        drop_partial_of(type);
        drop_instance_types_of(type);
        m_instances.rebuild_known_hostnames();
    }

private:
    monitor_options &m_opts;
    changed_callback m_changed_cb;
    forget_callback m_forget_cb;
    monitor_instances &m_instances;

    // The refresh schedule goes with its anchor record; schedules would otherwise grow without bound.
    void expire_srv(const record_srv &r)
    {
        m_forget_cb(r.name);
        auto it = m_instances.live.find(r.name);
        if(it == m_instances.live.end())
        {
            m_instances.partial.erase(r.name);
            m_instances.goodbye.erase(r.name);
            return;
        }

        resolved_service last_known = it->second;
        m_instances.live.erase(it);
        m_instances.partial.erase(r.name);
        loss_reason reason = m_instances.goodbye.erase(r.name) > 0 ? loss_reason::goodbye : loss_reason::timeout;
        if(m_opts.on_lost)
            m_opts.on_lost(last_known, reason);
        m_changed_cb();
    }

    void expire_address(const dns_name &host, const std::string &address, dns_type type)
    {
        for(auto &[inst_name, svc] : m_instances.live)
        {
            if(svc.hostname != host)
                continue;
            auto &addrs = service_addresses(svc, type);
            auto it = std::ranges::find(addrs, address);
            if(it != addrs.end())
            {
                addrs.erase(it);
                if(m_opts.on_updated)
                    m_opts.on_updated(svc, update_event::removed, type);
                m_changed_cb();
            }
        }
    }

    void expire_txt(const record_txt &r)
    {
        auto it = m_instances.live.find(r.name);
        if(it == m_instances.live.end() || !erase_txt_keys(it->second.txt_entries, r.entries))
            return;
        if(m_opts.on_updated)
            m_opts.on_updated(it->second, update_event::removed, dns_type::txt);
        m_changed_cb();
    }

    void drop_live_of(const dns_name &type)
    {
        std::vector<dns_name> to_remove;
        for(const auto &[inst_name, svc] : m_instances.live)
        {
            if(auto tit = m_instances.instance_type.find(inst_name); tit != m_instances.instance_type.end())
            {
                if(tit->second == type)
                    to_remove.push_back(inst_name);
            }
        }
        for(const auto &inst_name : to_remove)
        {
            if(auto it = m_instances.live.find(inst_name); it != m_instances.live.end())
            {
                if(m_opts.on_lost)
                    m_opts.on_lost(it->second, loss_reason::unwatched);
                m_instances.live.erase(it);
            }
        }
    }

    void drop_partial_of(const dns_name &type)
    {
        std::vector<dns_name> to_remove;
        for(auto &[inst_name, inc] : m_instances.partial)
        {
            if(inc.service_type == type)
                to_remove.push_back(inst_name);
        }
        for(const auto &inst_name : to_remove)
            m_instances.partial.erase(inst_name);
    }

    // Goodbye marks and refresh schedules are per instance: only the unwatched type's go.
    void drop_instance_types_of(const dns_name &type)
    {
        std::vector<dns_name> to_remove;
        for(auto &[inst_name, svc_type] : m_instances.instance_type)
        {
            if(svc_type == type)
                to_remove.push_back(inst_name);
        }
        for(const auto &inst_name : to_remove)
        {
            m_instances.instance_type.erase(inst_name);
            m_instances.goodbye.erase(inst_name);
            m_forget_cb(inst_name);
        }
    }
};

}

#endif
