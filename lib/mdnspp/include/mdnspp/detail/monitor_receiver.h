#ifndef HPP_GUARD_MDNSPP_DETAIL_MONITOR_RECEIVER_H
#define HPP_GUARD_MDNSPP_DETAIL_MONITOR_RECEIVER_H

#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_frame.h"
#include "mdnspp/detail/locked_snapshot.h"
#include "mdnspp/detail/monitor_resolver.h"
#include "mdnspp/detail/monitor_schedule.h"
#include "mdnspp/detail/monitor_instances.h"

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/record_cache.h"
#include "mdnspp/resolved_service.h"

#include <span>
#include <vector>
#include <cstddef>
#include <utility>
#include <variant>
#include <type_traits>

namespace mdnspp::detail {

// Only PTR records of watched types, SRV and TXT records of tracked instances and address records of
// known hostnames are cached and processed; everything else is dropped.
template <typename Clock>
class monitor_receiver
{
public:
    monitor_receiver(record_cache<Clock> &cache, const monitor_instances &instances,
                     const monitor_schedule<Clock> &schedule, monitor_resolver &resolver)
        : m_snapshot()
        , m_cache(cache)
        , m_resolver(resolver)
        , m_instances(instances)
        , m_schedule(schedule)
    {
    }

    // Only responses (QR=1) are consumed: records in queries are known-answer lists of other queriers
    // (RFC 6762 section 7.1) or probe proposals, which must not be cached (section 8.2). Responses carry
    // answers in the Answer and Additional sections only, so their Authority section is ignored too.
    bool handle_packet(const endpoint &sender, std::span<std::byte> data)
    {
        bool relevant{false};
        walk_dns_frame(data, sender, [&](mdns_record_variant rec, const dns_frame_header &header, dns_section section)
        {
            if(!header.is_response() || section == dns_section::authority)
                return;
            if(!is_relevant(rec))
                return;
            relevant = true;
            m_cache.insert(rec, sender);
            m_resolver.process(std::move(rec));
        });
        return relevant;
    }

    // The TTL fields come from the cached SRV record; if it already expired the zeroed defaults stay.
    void publish()
    {
        std::vector<resolved_service> snap;
        snap.reserve(m_instances.live.size());
        for(const auto &[name, svc] : m_instances.live)
        {
            resolved_service entry = svc;
            auto srv_entries = m_cache.find(name, dns_type::srv);
            if(!srv_entries.empty())
            {
                entry.wire_ttl = srv_entries.front().wire_ttl;
                entry.ttl_remaining = srv_entries.front().ttl_remaining;
            }
            snap.push_back(std::move(entry));
        }
        m_snapshot.publish(std::move(snap));
    }

    std::vector<resolved_service> services() const { return m_snapshot.copy(); }

private:
    locked_snapshot<resolved_service> m_snapshot;
    record_cache<Clock> &m_cache;
    monitor_resolver &m_resolver;
    const monitor_instances &m_instances;
    const monitor_schedule<Clock> &m_schedule;

    bool is_relevant(const mdns_record_variant &rec) const
    {
        return std::visit([this](const auto &r) -> bool
        {
            using T = std::remove_cvref_t<decltype(r)>;

            if constexpr (std::is_same_v<T, record_ptr>)
                return m_schedule.watching(r.name);
            else if constexpr (std::is_same_v<T, record_srv> || std::is_same_v<T, record_txt>)
                return m_instances.tracks(r.name);
            else if constexpr (std::is_same_v<T, record_a> || std::is_same_v<T, record_aaaa>)
                return m_instances.known_hostnames.contains(r.name);
            else
                return false;
        }, rec);
    }
};

}

#endif
