#ifndef HPP_GUARD_MDNSPP_TC_ACCUMULATOR_H
#define HPP_GUARD_MDNSPP_TC_ACCUMULATOR_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"

#include <chrono>
#include <vector>
#include <optional>
#include <utility>
#include <functional>
#include <unordered_map>

namespace mdnspp::detail {

struct endpoint_hash
{
    std::size_t operator()(const endpoint &ep) const noexcept
    {
        auto h1 = std::hash<std::string>{}(ep.address);
        auto h2 = std::hash<uint16_t>{}(ep.port);
        return h1 ^ (h2 << 16);
    }
};

template <typename Clock = std::chrono::steady_clock>
struct tc_accumulator
{
    using time_point = typename Clock::time_point;

    void accumulate(const endpoint &source, std::vector<mdns_record_variant> new_records,
                    std::chrono::milliseconds tc_wait)
    {
        (void)tc_wait; // timer is logical: inserted_at is set once on first packet

        auto it = m_entries.find(source);
        if (it != m_entries.end())
        {
            // Continuation packet: append records, do NOT reset inserted_at
            auto &records = it->second.records;
            records.insert(records.end(),
                           std::make_move_iterator(new_records.begin()),
                           std::make_move_iterator(new_records.end()));
        }
        else
        {
            // First packet from this source: arm the timer
            m_entries.emplace(source, entry{std::move(new_records), Clock::now()});
        }
    }

    [[nodiscard]] std::optional<std::vector<mdns_record_variant>>
    take_if_ready(const endpoint &source, time_point now,
                  std::chrono::milliseconds tc_wait)
    {
        auto it = m_entries.find(source);
        if (it == m_entries.end())
            return std::nullopt;

        if (now >= it->second.inserted_at + tc_wait)
        {
            auto records = std::move(it->second.records);
            m_entries.erase(it);
            return records;
        }

        return std::nullopt;
    }

    void clear() noexcept { m_entries.clear(); }

    [[nodiscard]] bool empty() const noexcept { return m_entries.empty(); }

    [[nodiscard]] bool has_pending(const endpoint &source) const
    {
        return m_entries.contains(source);
    }

private:
    struct entry
    {
        std::vector<mdns_record_variant> records;
        time_point inserted_at{};
    };

    std::unordered_map<endpoint, entry, endpoint_hash> m_entries;
};

}

#endif
