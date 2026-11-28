#ifndef HPP_GUARD_MDNSPP_DETAIL_MONITOR_INSTANCES_H
#define HPP_GUARD_MDNSPP_DETAIL_MONITOR_INSTANCES_H

#include "mdnspp/detail/dns_enums.h"

#include "mdnspp/records.h"
#include "mdnspp/dns_name.h"
#include "mdnspp/resolved_service.h"

#include <string>
#include <vector>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>

namespace mdnspp::detail {

struct incomplete_instance
{
    dns_name service_type;
    bool has_srv{false};
    bool has_address{false};
    resolved_service partial;
};

// An instance named by a PTR record stays partial until its SRV and an address record arrived. Only
// A/AAAA records of known hostnames are accepted.
struct monitor_instances
{
    std::unordered_map<dns_name, dns_name> instance_type;
    std::unordered_map<dns_name, incomplete_instance> partial;
    std::unordered_map<dns_name, resolved_service> live;
    std::unordered_set<dns_name> known_hostnames;
    std::unordered_set<dns_name> goodbye;

    bool tracks(const dns_name &instance) const
    {
        return partial.contains(instance) || live.contains(instance);
    }

    // Hostnames may be shared across service types, so only hosts still used by a live or partial
    // instance remain known.
    void rebuild_known_hostnames()
    {
        known_hostnames.clear();
        for(const auto &[name, svc] : live)
        {
            if(!svc.hostname.empty())
                known_hostnames.insert(svc.hostname);
        }
        for(const auto &[name, inc] : partial)
        {
            if(!inc.partial.hostname.empty())
                known_hostnames.insert(inc.partial.hostname);
        }
    }
};

inline std::vector<std::string> &service_addresses(resolved_service &svc, dns_type type)
{
    return type == dns_type::a ? svc.ipv4_addresses : svc.ipv6_addresses;
}

// The last value wins per key; returns whether an entry was added or changed.
inline bool merge_txt(std::vector<service_txt> &dst, const std::vector<service_txt> &src)
{
    bool changed{false};
    for(const auto &e : src)
    {
        auto it = std::ranges::find_if(dst, [&](const service_txt &x) { return x.key == e.key; });
        if(it == dst.end())
        {
            dst.push_back(e);
            changed = true;
        }
        else if(it->value != e.value)
        {
            it->value = e.value;
            changed = true;
        }
    }
    return changed;
}

inline bool erase_txt_keys(std::vector<service_txt> &dst, const std::vector<service_txt> &expired)
{
    bool changed{false};
    for(const auto &e : expired)
    {
        auto it = std::ranges::find_if(dst, [&](const service_txt &x) { return x.key == e.key; });
        if(it != dst.end())
        {
            dst.erase(it);
            changed = true;
        }
    }
    return changed;
}

}

#endif
