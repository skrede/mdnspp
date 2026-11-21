#ifndef HPP_GUARD_MDNSPP_DETAIL_MONITOR_RESOLVER_H
#define HPP_GUARD_MDNSPP_DETAIL_MONITOR_RESOLVER_H

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/monitor_instances.h"

#include "mdnspp/records.h"
#include "mdnspp/dns_name.h"
#include "mdnspp/monitor_options.h"
#include "mdnspp/resolved_service.h"

#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <variant>
#include <algorithm>
#include <type_traits>

namespace mdnspp::detail {

// refresh_cb receives every SRV with a positive TTL of a tracked instance; changed_cb follows every
// change to a live instance.
class monitor_resolver
{
public:
    using changed_callback = move_only_function<void()>;
    using refresh_callback = move_only_function<void(const dns_name &, uint32_t)>;

    monitor_resolver(monitor_instances &instances, monitor_options &opts, changed_callback changed_cb,
                     refresh_callback refresh_cb)
        : m_opts(opts)
        , m_changed_cb(std::move(changed_cb))
        , m_refresh_cb(std::move(refresh_cb))
        , m_instances(instances)
    {
    }

    void process(mdns_record_variant rec)
    {
        std::visit([this](auto &&r)
        {
            using T = std::remove_cvref_t<decltype(r)>;
            if constexpr (std::is_same_v<T, record_ptr>)
                process_ptr(r);
            else if constexpr (std::is_same_v<T, record_srv>)
                process_srv(r);
            else if constexpr (std::is_same_v<T, record_a>)
                process_address(r.name, r.address_string, dns_type::a);
            else if constexpr (std::is_same_v<T, record_aaaa>)
                process_address(r.name, r.address_string, dns_type::aaaa);
            else if constexpr (std::is_same_v<T, record_txt>)
                process_txt(r);
        }, std::move(rec));
    }

private:
    monitor_options &m_opts;
    changed_callback m_changed_cb;
    refresh_callback m_refresh_cb;
    monitor_instances &m_instances;

    void process_ptr(const record_ptr &r)
    {
        const dns_name &inst = r.ptr_name;
        if(m_instances.tracks(inst))
            return;
        auto &partial = m_instances.partial[inst];
        partial.service_type = r.name;
        partial.partial.instance_name = inst;
        m_instances.instance_type[inst] = r.name;
    }

    // A zero TTL marks the instance for goodbye reporting when its SRV record expires.
    void process_srv(const record_srv &r)
    {
        if(r.ttl == 0)
            m_instances.goodbye.insert(r.name);

        if(auto it = m_instances.partial.find(r.name); it != m_instances.partial.end())
            update_partial_srv(it->second, r);
        else if(auto lit = m_instances.live.find(r.name); lit != m_instances.live.end())
            update_live_srv(lit->second, r);
    }

    void update_partial_srv(incomplete_instance &inc, const record_srv &r)
    {
        inc.has_srv = true;
        inc.partial.hostname = r.srv_name;
        inc.partial.port = r.port;
        m_instances.known_hostnames.insert(r.srv_name);
        if(r.ttl > 0)
            m_refresh_cb(r.name, r.ttl);
        check_resolved(r.name);
    }

    void update_live_srv(resolved_service &svc, const record_srv &r)
    {
        if(r.ttl > 0)
            m_refresh_cb(r.name, r.ttl);
        bool changed = (svc.hostname != r.srv_name || svc.port != r.port);
        if(!changed)
            return;
        svc.hostname = r.srv_name;
        svc.port = r.port;
        m_instances.known_hostnames.insert(r.srv_name);
        if(m_opts.on_updated)
            m_opts.on_updated(svc, update_event::added, dns_type::srv);
        m_changed_cb();
    }

    void process_address(const dns_name &host, const std::string &address, dns_type type)
    {
        if(add_partial_address(host, address, type))
            resolve_partials_of(host);
        add_live_address(host, address, type);
    }

    bool add_partial_address(const dns_name &host, const std::string &address, dns_type type)
    {
        bool any_updated{false};
        for(auto &[inst_name, inc] : m_instances.partial)
        {
            if(inc.partial.hostname != host)
                continue;
            auto &addrs = service_addresses(inc.partial, type);
            if(std::ranges::find(addrs, address) == addrs.end())
            {
                addrs.push_back(address);
                inc.has_address = true;
                any_updated = true;
            }
        }
        return any_updated;
    }

    void resolve_partials_of(const dns_name &host)
    {
        std::vector<dns_name> to_check;
        for(auto &[inst_name, inc] : m_instances.partial)
        {
            if(inc.partial.hostname == host && inc.has_srv && inc.has_address)
                to_check.push_back(inst_name);
        }
        for(const auto &inst_name : to_check)
            check_resolved(inst_name);
    }

    void add_live_address(const dns_name &host, const std::string &address, dns_type type)
    {
        for(auto &[inst_name, svc] : m_instances.live)
        {
            if(svc.hostname != host)
                continue;
            auto &addrs = service_addresses(svc, type);
            if(std::ranges::find(addrs, address) == addrs.end())
            {
                addrs.push_back(address);
                if(m_opts.on_updated)
                    m_opts.on_updated(svc, update_event::added, type);
                m_changed_cb();
            }
        }
    }

    void process_txt(const record_txt &r)
    {
        if(auto it = m_instances.partial.find(r.name); it != m_instances.partial.end())
        {
            merge_txt(it->second.partial.txt_entries, r.entries);
            return;
        }
        auto it = m_instances.live.find(r.name);
        if(it == m_instances.live.end() || !merge_txt(it->second.txt_entries, r.entries))
            return;
        if(m_opts.on_updated)
            m_opts.on_updated(it->second, update_event::added, dns_type::txt);
        m_changed_cb();
    }

    void check_resolved(const dns_name &inst_name)
    {
        auto it = m_instances.partial.find(inst_name);
        if(it == m_instances.partial.end() || !it->second.has_srv || !it->second.has_address)
            return;
        resolved_service svc = std::move(it->second.partial);
        m_instances.partial.erase(it);
        m_instances.live.emplace(inst_name, svc);
        if(m_opts.on_found)
            m_opts.on_found(svc);
        m_changed_cb();
    }
};

}

#endif
