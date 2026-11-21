#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVICE_AGGREGATION_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVICE_AGGREGATION_H

#include "mdnspp/records.h"
#include "mdnspp/resolved_service.h"

#include <span>
#include <vector>
#include <utility>
#include <variant>
#include <algorithm>
#include <unordered_map>

namespace mdnspp::detail {

struct aggregation_entry
{
    resolved_service svc;
};

using aggregation_services = std::unordered_map<dns_name, aggregation_entry>;
using aggregation_hosts = std::unordered_map<dns_name, std::vector<dns_name>>;

struct instance_pass
{
    aggregation_services &svc_map;
    aggregation_hosts &host_to_instances;

    void operator()(const record_ptr &r) const
    {
        if(!svc_map.contains(r.ptr_name))
        {
            resolved_service svc;
            svc.instance_name = r.ptr_name;
            svc_map.emplace(r.ptr_name, aggregation_entry{std::move(svc)});
        }
    }

    void operator()(const record_srv &r) const
    {
        if(auto it = svc_map.find(r.name); it != svc_map.end())
        {
            it->second.svc.hostname = r.srv_name;
            it->second.svc.port = r.port;
            if(auto hi = host_to_instances.find(r.srv_name); hi != host_to_instances.end())
                hi->second.push_back(r.name);
            else
                host_to_instances.emplace(r.srv_name, std::vector<dns_name>{r.name});
        }
    }

    void operator()(const record_txt &r) const
    {
        if(auto it = svc_map.find(r.name); it != svc_map.end())
        {
            auto &entries = it->second.svc.txt_entries;
            for(const auto &e : r.entries)
            {
                auto existing = std::ranges::find_if(entries,
                                                     [&](const service_txt &x) { return x.key == e.key; });
                if(existing != entries.end())
                    *existing = e;
                else
                    entries.push_back(e);
            }
        }
    }

    void operator()(const record_a &) const {}
    void operator()(const record_aaaa &) const {}
};

struct address_pass
{
    aggregation_services &svc_map;
    aggregation_hosts &host_to_instances;

    void operator()(const record_a &r) const
    {
        auto host_it = host_to_instances.find(r.name);
        if(host_it == host_to_instances.end())
            return;
        for(const auto &inst_name : host_it->second)
        {
            auto svc_it = svc_map.find(inst_name);
            if(svc_it == svc_map.end())
                continue;
            auto &addrs = svc_it->second.svc.ipv4_addresses;
            if(std::ranges::find(addrs, r.address_string) == addrs.end())
                addrs.push_back(r.address_string);
        }
    }

    void operator()(const record_aaaa &r) const
    {
        auto host_it = host_to_instances.find(r.name);
        if(host_it == host_to_instances.end())
            return;
        for(const auto &inst_name : host_it->second)
        {
            auto svc_it = svc_map.find(inst_name);
            if(svc_it == svc_map.end())
                continue;
            auto &addrs = svc_it->second.svc.ipv6_addresses;
            if(std::ranges::find(addrs, r.address_string) == addrs.end())
                addrs.push_back(r.address_string);
        }
    }

    void operator()(const record_ptr &) const {}
    void operator()(const record_srv &) const {}
    void operator()(const record_txt &) const {}
};

inline std::vector<resolved_service> collect_services(aggregation_services &svc_map)
{
    std::vector<resolved_service> result;
    result.reserve(svc_map.size());
    for(auto &[key, entry] : svc_map)
        result.push_back(std::move(entry.svc));
    return result;
}

}

namespace mdnspp {

inline std::vector<resolved_service> aggregate(std::span<const mdns_record_variant> records)
{
    detail::aggregation_services svc_map;
    detail::aggregation_hosts host_to_instances;

    for(const auto &rec : records)
        std::visit(detail::instance_pass{svc_map, host_to_instances}, rec);

    // Addresses join in a second pass, so A and AAAA records that precede their SRV still correlate.
    for(const auto &rec : records)
        std::visit(detail::address_pass{svc_map, host_to_instances}, rec);

    return detail::collect_services(svc_map);
}

}

#endif
