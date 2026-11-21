#ifndef HPP_GUARD_MDNSPP_DETAIL_MONITOR_SCHEDULE_H
#define HPP_GUARD_MDNSPP_DETAIL_MONITOR_SCHEDULE_H

#include "mdnspp/detail/ttl_refresh.h"
#include "mdnspp/detail/query_backoff.h"

#include "mdnspp/dns_name.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/record_cache.h"
#include "mdnspp/monitor_options.h"

#include <chrono>
#include <random>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <optional>
#include <unordered_map>

namespace mdnspp::detail {

// Per-name backoff (RFC 6762 section 5.2): every watch keeps its own deadline, so one watch's fire
// point or a TTL-refresh fire point never triggers a premature query for another name.
template <typename Clock>
class monitor_schedule
{
    using time_point = typename Clock::time_point;

    struct watched_type_state
    {
        detail::query_backoff_state backoff;
        typename Clock::time_point next_query_at{};
    };

public:
    monitor_schedule()
        : m_watches()
        , m_refresh_schedules()
    {
    }

    template <typename Delay>
    void add_watch(dns_name type, Delay &&first_delay)
    {
        auto [it, inserted] = m_watches.try_emplace(std::move(type));
        if(inserted)
            it->second.next_query_at = Clock::now() + first_delay();
    }

    bool watching(const dns_name &type) const { return m_watches.contains(type); }

    void remove_watch(const dns_name &type) { m_watches.erase(type); }

    // The first query is measured from start, not from watch().
    template <typename Delay>
    void reseed_first_queries(Delay &&first_delay)
    {
        auto now = Clock::now();
        for(auto &[svc_type, ws] : m_watches)
        {
            if(ws.backoff.first)
                ws.next_query_at = now + first_delay();
        }
    }

    // Without a due query or refresh the monitor still wakes once a second to sweep expired records.
    time_point next_wakeup(monitor_mode mode, time_point now) const
    {
        std::optional<time_point> next;
        if(mode == monitor_mode::discover)
        {
            for(const auto &[svc_type, ws] : m_watches)
                keep_earliest(next, ws.next_query_at);
        }
        if(refreshes(mode))
        {
            for(const auto &[key, sched] : m_refresh_schedules)
            {
                if(sched.next_idx < sched.fire_at.size())
                    keep_earliest(next, sched.fire_at[sched.next_idx]);
            }
        }
        return next.value_or(now + std::chrono::seconds{1});
    }

    std::vector<dns_name> take_due_watches(monitor_mode mode, time_point now, const mdns_options &opts)
    {
        std::vector<dns_name> due;
        if(mode != monitor_mode::discover)
            return due;
        for(auto &[svc_type, ws] : m_watches)
        {
            if(ws.next_query_at > now)
                continue;
            auto interval = detail::advance_backoff(ws.backoff, opts);
            ws.next_query_at = now + interval;
            due.push_back(svc_type);
        }
        return due;
    }

    // One name per passed fire point; exhausted schedules are pruned until a fresh record rebuilds them.
    std::vector<dns_name> take_due_refreshes(monitor_mode mode, time_point now)
    {
        std::vector<dns_name> due;
        if(!refreshes(mode))
            return due;
        for(auto it = m_refresh_schedules.begin(); it != m_refresh_schedules.end();)
        {
            auto &[key, sched] = *it;
            while(sched.next_idx < sched.fire_at.size() && sched.fire_at[sched.next_idx] <= now)
            {
                due.push_back(key.name);
                ++sched.next_idx;
            }
            if(sched.next_idx >= sched.fire_at.size())
                it = m_refresh_schedules.erase(it);
            else
                ++it;
        }
        return due;
    }

    void rebuild_refresh(const record_name_type &key, uint32_t wire_ttl, const mdns_options &opts,
                         std::mt19937 &rng)
    {
        auto inserted_at = Clock::now();
        m_refresh_schedules[key] = make_refresh_schedule<Clock>(wire_ttl, opts, inserted_at, rng);
    }

    void drop_refresh(const record_name_type &key) { m_refresh_schedules.erase(key); }

    std::size_t refresh_count() const noexcept { return m_refresh_schedules.size(); }

    static bool refreshes(monitor_mode mode) noexcept
    {
        return mode == monitor_mode::discover || mode == monitor_mode::ttl_refresh;
    }

private:
    std::unordered_map<dns_name, watched_type_state> m_watches;
    std::unordered_map<record_name_type, ttl_refresh_schedule<Clock>, record_name_type_hash> m_refresh_schedules;

    static void keep_earliest(std::optional<time_point> &next, time_point candidate)
    {
        if(!next || candidate < *next)
            next = candidate;
    }
};

}

#endif
