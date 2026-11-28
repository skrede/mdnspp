#ifndef HPP_GUARD_MDNSPP_DETAIL_RECORD_CACHE_SLOT_H
#define HPP_GUARD_MDNSPP_DETAIL_RECORD_CACHE_SLOT_H

#include "mdnspp/detail/record_identity.h"

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/cache_entry.h"

#include <chrono>
#include <vector>
#include <cstdint>
#include <utility>
#include <optional>
#include <algorithm>

namespace mdnspp::detail {

template <typename TimePoint>
struct record_cache_slot
{
    mdns_record_variant record;
    endpoint origin;
    bool cache_flush{false};
    uint32_t wire_ttl{0};
    TimePoint inserted_at{};
    std::optional<TimePoint> flush_deadline{};
};

struct cache_flush_marks
{
    cache_entry authoritative;
    std::vector<cache_entry> affected;
};

template <typename TimePoint>
bool is_expired(const record_cache_slot<TimePoint> &e, TimePoint now)
{
    if (now >= e.inserted_at + std::chrono::seconds(e.wire_ttl))
        return true;
    if (e.flush_deadline && now >= *e.flush_deadline)
        return true;
    return false;
}

template <typename TimePoint>
cache_entry to_cache_entry(const record_cache_slot<TimePoint> &e, TimePoint now)
{
    auto deadline = e.inserted_at + std::chrono::seconds(e.wire_ttl);
    auto remaining = std::chrono::duration_cast<std::chrono::nanoseconds>(deadline - now);

    return cache_entry{
        .record = e.record,
        .origin = e.origin,
        .cache_flush = e.cache_flush,
        .wire_ttl = e.wire_ttl,
        .ttl_remaining = remaining,
    };
}

// RFC 6762 section 10.1: a goodbye record (TTL 0) is retained for goodbye_grace.
inline uint32_t retained_ttl(uint32_t ttl, std::chrono::seconds grace)
{
    auto capped = (std::min)(grace.count(), std::chrono::seconds::rep{UINT32_MAX});
    return (ttl == 0) ? static_cast<uint32_t>(capped) : ttl;
}

template <typename Iterator, typename TimePoint>
bool refresh_match(std::pair<Iterator, Iterator> range, const mdns_record_variant &rec, endpoint &origin, bool flush,
                   uint32_t effective_ttl, TimePoint now)
{
    auto [it, end] = range;
    for (; it != end; ++it)
    {
        if (record_identity_equal(it->second.record, rec))
        {
            it->second.inserted_at = now;
            it->second.wire_ttl = effective_ttl;
            it->second.cache_flush = flush;
            it->second.origin = std::move(origin);
            it->second.flush_deadline.reset();
            return true;
        }
    }
    return false;
}

template <typename Map, typename TimePoint>
std::vector<cache_entry> take_expired(Map &entries, TimePoint now)
{
    std::vector<cache_entry> expired;
    for (auto it = entries.begin(); it != entries.end(); )
    {
        if (is_expired(it->second, now))
        {
            expired.push_back(to_cache_entry(it->second, now));
            it = entries.erase(it);
        }
        else
        {
            ++it;
        }
    }
    return expired;
}

template <typename Iterator, typename TimePoint>
cache_flush_marks mark_cache_flush(std::pair<Iterator, Iterator> range, const endpoint &origin, TimePoint now,
                                   std::chrono::seconds grace)
{
    auto deadline = now + grace;
    // RFC 6762 section 10.2: records received within the last second are exempt, so that bursts from several
    // interfaces or co-located responders are not flushed.
    auto exemption_cutoff = now - std::chrono::seconds(1);
    cache_flush_marks marks;
    auto [it, end] = range;
    for (; it != end; ++it)
    {
        auto &entry = it->second;
        if (entry.origin == origin)
        {
            if (entry.cache_flush)
                marks.authoritative = to_cache_entry(entry, now);
        }
        else if (entry.inserted_at <= exemption_cutoff)
        {
            if (!entry.flush_deadline || *entry.flush_deadline > deadline)
                entry.flush_deadline = deadline;
            marks.affected.push_back(to_cache_entry(entry, now));
        }
    }
    return marks;
}

}

#endif
