#ifndef HPP_GUARD_MDNSPP_RESOLVED_SERVICE_H
#define HPP_GUARD_MDNSPP_RESOLVED_SERVICE_H

#include "mdnspp/records.h"

#include <algorithm>
#include <cstdint>
#include <ranges>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace mdnspp {

// resolved_service — public vocabulary type produced by aggregate().
//
// Represents a fully-correlated mDNS service instance following RFC 6763
// name-chain correlation (PTR -> SRV -> TXT -> A/AAAA).
//
// Fields:
//   instance_name   — fully-qualified service instance name (PTR.ptr_name)
//   hostname        — target hostname from SRV record (SRV.srv_name)
//   port            — service port from SRV record
//   txt_entries     — TXT key/value pairs (reuses service_txt from records.h)
//   ipv4_addresses  — correlated IPv4 address strings from A records
//   ipv6_addresses  — correlated IPv6 address strings from AAAA records
struct resolved_service
{
    std::string              instance_name;
    std::string              hostname;
    uint16_t                 port{0};
    std::vector<service_txt> txt_entries;
    std::vector<std::string> ipv4_addresses;
    std::vector<std::string> ipv6_addresses;
};

// aggregate() — correlate a flat sequence of mDNS records into resolved_service values.
//
// Implements RFC 6763 name-chain correlation:
//   PTR.ptr_name  == instance name  (seeds the output — only PTR records seed entries)
//   SRV.name      == instance name  (matches PTR.ptr_name; provides hostname + port)
//   SRV.srv_name  == target host    (used to join A/AAAA records)
//   TXT.name      == instance name  (matches PTR.ptr_name)
//   A.name / AAAA.name == SRV.srv_name
//
// Two-pass algorithm ensures A/AAAA records arriving before their SRV are still
// correlated correctly.
//
// Deduplication:
//   - IP addresses: by value (std::ranges::find)
//   - TXT entries:  by key   (latest value wins)
//   - SRV port/hostname: latest SRV record wins
//
// Partial services (missing SRV, TXT, or address records) are included with
// empty fields — they are never dropped.
inline std::vector<resolved_service> aggregate(std::span<const mdns_record_variant> records)
{
    // Working state per service instance
    struct svc_entry
    {
        resolved_service svc;
    };

    // Pass 1: build service map keyed by instance name.
    // host_to_instances maps SRV.srv_name -> list of instance names.
    std::unordered_map<std::string, svc_entry>               svc_map;
    std::unordered_map<std::string, std::vector<std::string>> host_to_instances;

    for (const auto& rec : records)
    {
        std::visit([&]<typename T>(const T& r) {
            if constexpr (std::is_same_v<T, record_ptr>)
            {
                // PTR seeds a new entry (insert_or_assign keeps existing if already seeded)
                if (!svc_map.contains(r.ptr_name))
                    svc_map.emplace(r.ptr_name, svc_entry{resolved_service{.instance_name = r.ptr_name}});
            }
            else if constexpr (std::is_same_v<T, record_srv>)
            {
                if (auto it = svc_map.find(r.name); it != svc_map.end())
                {
                    it->second.svc.hostname = r.srv_name;
                    it->second.svc.port     = r.port;
                    // Record the host -> instance mapping for address correlation
                    host_to_instances[r.srv_name].push_back(r.name);
                }
            }
            else if constexpr (std::is_same_v<T, record_txt>)
            {
                if (auto it = svc_map.find(r.name); it != svc_map.end())
                {
                    auto& entries = it->second.svc.txt_entries;
                    for (const auto& e : r.entries)
                    {
                        // Deduplicate by key — latest value wins
                        auto existing = std::ranges::find_if(entries,
                            [&](const service_txt& x){ return x.key == e.key; });
                        if (existing != entries.end())
                            *existing = e;
                        else
                            entries.push_back(e);
                    }
                }
            }
        }, rec);
    }

    // Pass 2: correlate A / AAAA records via host_to_instances.
    for (const auto& rec : records)
    {
        std::visit([&]<typename T>(const T& r) {
            if constexpr (std::is_same_v<T, record_a>)
            {
                auto host_it = host_to_instances.find(r.name);
                if (host_it == host_to_instances.end())
                    return;
                for (const auto& inst_name : host_it->second)
                {
                    auto svc_it = svc_map.find(inst_name);
                    if (svc_it == svc_map.end())
                        continue;
                    auto& addrs = svc_it->second.svc.ipv4_addresses;
                    if (std::ranges::find(addrs, r.address_string) == addrs.end())
                        addrs.push_back(r.address_string);
                }
            }
            else if constexpr (std::is_same_v<T, record_aaaa>)
            {
                auto host_it = host_to_instances.find(r.name);
                if (host_it == host_to_instances.end())
                    return;
                for (const auto& inst_name : host_it->second)
                {
                    auto svc_it = svc_map.find(inst_name);
                    if (svc_it == svc_map.end())
                        continue;
                    auto& addrs = svc_it->second.svc.ipv6_addresses;
                    if (std::ranges::find(addrs, r.address_string) == addrs.end())
                        addrs.push_back(r.address_string);
                }
            }
        }, rec);
    }

    // Collect results
    std::vector<resolved_service> result;
    result.reserve(svc_map.size());
    for (auto& [key, entry] : svc_map)
        result.push_back(std::move(entry.svc));

    return result;
}

// Convenience overload — accepts const reference to vector.
inline std::vector<resolved_service> aggregate(const std::vector<mdns_record_variant>& records)
{
    return aggregate(std::span<const mdns_record_variant>{records});
}

} // namespace mdnspp

#endif // HPP_GUARD_MDNSPP_RESOLVED_SERVICE_H
