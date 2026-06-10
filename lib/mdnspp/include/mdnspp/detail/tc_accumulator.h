#ifndef HPP_GUARD_MDNSPP_DETAIL_TC_ACCUMULATOR_H
#define HPP_GUARD_MDNSPP_DETAIL_TC_ACCUMULATOR_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"

#include "mdnspp/detail/hash_combine.h"

#include <chrono>
#include <vector>
#include <utility>
#include <optional>
#include <algorithm>
#include <functional>
#include <unordered_map>

namespace mdnspp::detail {

struct endpoint_hash
{
    std::size_t operator()(const endpoint &ep) const noexcept
    {
        auto h1 = std::hash<std::string>{}(ep.address);
        auto h2 = std::hash<uint16_t>{}(ep.port);
        return hash_combine(h1, h2);
    }
};

// Accumulates known-answer records from truncated (TC) queries per source
// (RFC 6762 §7.2). Each source carries its own drain deadline; the owner arms
// one timer for the earliest deadline and drains all expired sources on fire.
template <typename Clock = std::chrono::steady_clock>
struct tc_accumulator
{
    using time_point = typename Clock::time_point;

    // Bounds memory growth from spoofed source endpoints; when full, the entry
    // with the earliest deadline (oldest) is dropped to admit the new source.
    static constexpr std::size_t max_pending_sources = 64;

    void accumulate(const endpoint &source, std::vector<mdns_record_variant> new_records,
                    std::chrono::milliseconds tc_wait)
    {
        auto it = m_entries.find(source);
        if(it != m_entries.end())
        {
            // Continuation packet: append records, do NOT reset the deadline
            auto &records = it->second.records;
            records.insert(records.end(),
                           std::make_move_iterator(new_records.begin()),
                           std::make_move_iterator(new_records.end()));
            return;
        }

        if(m_entries.size() >= max_pending_sources)
            drop_oldest();

        m_entries.emplace(source, entry{std::move(new_records), Clock::now() + tc_wait});
    }

    // Earliest pending deadline, or nullopt when no sources are pending.
    [[nodiscard]] std::optional<time_point> next_deadline() const
    {
        std::optional<time_point> earliest;
        for(const auto &[source, e] : m_entries)
        {
            if(!earliest.has_value() || e.deadline < *earliest)
                earliest = e.deadline;
        }
        return earliest;
    }

    // Removes and returns the merged record sets of ALL sources whose deadline
    // has passed at `now`.
    [[nodiscard]] std::vector<std::pair<endpoint, std::vector<mdns_record_variant>>>
    take_expired(time_point now)
    {
        std::vector<std::pair<endpoint, std::vector<mdns_record_variant>>> expired;
        for(auto it = m_entries.begin(); it != m_entries.end();)
        {
            if(now >= it->second.deadline)
            {
                expired.emplace_back(it->first, std::move(it->second.records));
                it = m_entries.erase(it);
            }
            else
            {
                ++it;
            }
        }
        return expired;
    }

    void clear() noexcept { m_entries.clear(); }

    [[nodiscard]] bool empty() const noexcept { return m_entries.empty(); }

    [[nodiscard]] std::size_t size() const noexcept { return m_entries.size(); }

    [[nodiscard]] bool has_pending(const endpoint &source) const
    {
        return m_entries.contains(source);
    }

private:
    struct entry
    {
        std::vector<mdns_record_variant> records;
        time_point deadline{};
    };

    void drop_oldest()
    {
        auto oldest = std::min_element(m_entries.begin(), m_entries.end(),
            [](const auto &a, const auto &b) { return a.second.deadline < b.second.deadline; });
        if(oldest != m_entries.end())
            m_entries.erase(oldest);
    }

    std::unordered_map<endpoint, entry, endpoint_hash> m_entries;
};

}

#endif
