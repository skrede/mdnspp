#ifndef HPP_GUARD_MDNSPP_DETAIL_NIC_FAMILY_UNION_H
#define HPP_GUARD_MDNSPP_DETAIL_NIC_FAMILY_UNION_H

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/nic_group_family.h"
#include "mdnspp/detail/nic_group_collect.h"

#include "mdnspp/ip_address.h"
#include "mdnspp/monitor_options.h"
#include "mdnspp/resolved_service.h"
#include "mdnspp/network_interface.h"

#include <array>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <utility>
#include <optional>
#include <unordered_map>

namespace mdnspp::detail {

// Runs on the group's executor one handler at a time (the single-threaded run() contract). A user callback may re-enter
// or destroy the union, so each change is complete before a callback runs and nothing is touched after it returns.
class nic_family_union
{
    using family_views = std::array<std::optional<resolved_service>, address_families.size()>;

public:
    using found_callback = move_only_function<void(const resolved_service &)>;
    using updated_callback = move_only_function<void(const resolved_service &, update_event, dns_type)>;
    using lost_callback = move_only_function<void(const resolved_service &, loss_reason)>;

    nic_family_union(found_callback on_found, updated_callback on_updated, lost_callback on_lost)
        : m_lost_cb(std::move(on_lost))
        , m_found_cb(std::move(on_found))
        , m_updated_cb(std::move(on_updated))
        , m_services()
    {
    }

    void found(address_family family, const resolved_service &svc)
    {
        store(family, svc, update_event::added, std::nullopt);
    }

    void updated(address_family family, const resolved_service &svc, update_event event, dns_type type)
    {
        store(family, svc, event, type);
    }

    void lost(address_family family, const resolved_service &svc, loss_reason reason)
    {
        auto it = m_services.find(svc.instance_name.comparison_key());
        if(it == m_services.end())
            return;
        const std::optional<resolved_service> before = united(it->second);
        it->second[family_slot(family)].reset();
        const std::optional<resolved_service> after = united(it->second);
        if(!after)
        {
            m_services.erase(it);
            if(before)
                m_lost_cb(*before, reason);
        }
        else if(auto type = changed_record_type(*before, *after))
            m_updated_cb(*after, update_event::removed, *type);
    }

private:
    lost_callback m_lost_cb;
    found_callback m_found_cb;
    updated_callback m_updated_cb;
    std::unordered_map<std::string, family_views> m_services;

    void store(address_family family, const resolved_service &svc, update_event event, std::optional<dns_type> type)
    {
        family_views &views = m_services[svc.instance_name.comparison_key()];
        const std::optional<resolved_service> before = united(views);
        views[family_slot(family)] = svc;
        const resolved_service after = *united(views);
        if(!before)
            m_found_cb(after);
        else if(auto changed = changed_record_type(*before, after))
            m_updated_cb(after, event, type.value_or(*changed));
    }

    static std::optional<resolved_service> united(const family_views &views)
    {
        std::optional<resolved_service> result;
        for(const auto &view : views)
        {
            if(!view)
                continue;
            if(result)
                merge_into(*result, *view);
            else
                result = *view;
        }
        return result;
    }
};

using nic_family_unions = std::vector<std::unique_ptr<nic_family_union>>;

template <typename GroupOptions>
std::unique_ptr<nic_family_union> make_stamped_union(GroupOptions &grp, const network_interface &nic)
{
    return std::make_unique<nic_family_union>(
        [&grp, nic](const resolved_service &svc)
        {
            if(grp.on_found)
                grp.on_found(nic, svc);
        },
        [&grp, nic](const resolved_service &svc, update_event event, dns_type type)
        {
            if(grp.on_updated)
                grp.on_updated(nic, svc, event, type);
        },
        [&grp, nic](const resolved_service &svc, loss_reason reason)
        {
            if(grp.on_lost)
                grp.on_lost(nic, svc, reason);
        });
}

template <typename GroupOptions>
nic_family_union &union_for(nic_family_unions &unions, std::size_t element, GroupOptions &grp,
                            const network_interface &nic)
{
    if(unions.size() <= element)
        unions.resize(element + 1);
    if(!unions[element])
        unions[element] = make_stamped_union(grp, nic);
    return *unions[element];
}

inline void route_monitor_events(monitor_options &opts, nic_family_union &fan_in, address_family family)
{
    opts.on_found = [&fan_in, family](const resolved_service &svc)
    {
        fan_in.found(family, svc);
    };
    opts.on_updated = [&fan_in, family](const resolved_service &svc, update_event event, dns_type type)
    {
        fan_in.updated(family, svc, event, type);
    };
    opts.on_lost = [&fan_in, family](const resolved_service &svc, loss_reason reason)
    {
        fan_in.lost(family, svc, reason);
    };
}

}

#endif
