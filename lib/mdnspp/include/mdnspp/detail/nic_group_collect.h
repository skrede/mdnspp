#ifndef HPP_GUARD_MDNSPP_DETAIL_NIC_GROUP_COLLECT_H
#define HPP_GUARD_MDNSPP_DETAIL_NIC_GROUP_COLLECT_H

#include "mdnspp/detail/dns_enums.h"

#include "mdnspp/records.h"
#include "mdnspp/resolved_service.h"
#include "mdnspp/network_interface.h"
#include "mdnspp/nic_group_options.h"

#include <string>
#include <vector>
#include <cstddef>
#include <utility>
#include <optional>
#include <algorithm>
#include <unordered_map>

namespace mdnspp::detail {

inline void merge_addresses(std::vector<std::string> &into, const std::vector<std::string> &from)
{
    for(const auto &address : from)
    {
        if(std::ranges::find(into, address) == into.end())
            into.push_back(address);
    }
}

inline void merge_into(resolved_service &into, const resolved_service &from)
{
    merge_addresses(into.ipv4_addresses, from.ipv4_addresses);
    merge_addresses(into.ipv6_addresses, from.ipv6_addresses);
}

// TTLs and source_interface are not compared: TTLs change on every refresh and the interface is not the service.
inline std::optional<dns_type> changed_record_type(const resolved_service &before, const resolved_service &after)
{
    if(!std::ranges::is_permutation(before.ipv4_addresses, after.ipv4_addresses))
        return dns_type::a;
    if(!std::ranges::is_permutation(before.ipv6_addresses, after.ipv6_addresses))
        return dns_type::aaaa;
    if(!std::ranges::is_permutation(before.txt_entries, after.txt_entries))
        return dns_type::txt;
    if(before.hostname != after.hostname || before.port != after.port)
        return dns_type::srv;
    return std::nullopt;
}

class service_union
{
public:
    void add(const std::string &key, resolved_service svc)
    {
        auto [it, inserted] = m_index.try_emplace(key, m_services.size());
        if(inserted)
            m_services.push_back(std::move(svc));
        else
            merge_into(m_services[it->second], svc);
    }

    std::vector<resolved_service> take() { return std::move(m_services); }

private:
    std::unordered_map<std::string, std::size_t> m_index;
    std::vector<resolved_service> m_services;
};

template <typename Slots>
std::vector<resolved_service> collect_services(const Slots &slots, dedup_mode mode)
{
    service_union services;
    slots.visit_monitors([&services, mode](const network_interface &nic, const auto &inst)
    {
        for(auto svc : inst.services())
        {
            // ASCII-folded key: case variants of one instance observed on different interfaces merge to one entry
            // (RFC 6762 section 16).
            std::string key = svc.instance_name.comparison_key();
            if(mode == dedup_mode::per_interface)
                key = std::to_string(nic.index) + '/' + key;
            svc.source_interface = nic;
            services.add(key, std::move(svc));
        }
    });
    return services.take();
}

}

#endif
