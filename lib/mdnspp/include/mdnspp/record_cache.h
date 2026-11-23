#ifndef HPP_GUARD_MDNSPP_RECORD_CACHE_H
#define HPP_GUARD_MDNSPP_RECORD_CACHE_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/cache_entry.h"
#include "mdnspp/cache_options.h"

#include "mdnspp/detail/record_identity.h"
#include "mdnspp/detail/record_cache_slot.h"

#include <mutex>
#include <chrono>
#include <vector>
#include <utility>
#include <shared_mutex>
#include <system_error>
#include <unordered_map>

namespace mdnspp {

template <typename Clock = std::chrono::steady_clock>
class record_cache
{
    using time_point = typename Clock::time_point;
    using internal_entry = detail::record_cache_slot<time_point>;
    using key_type = detail::record_name_type;
    using map_type = std::unordered_multimap<key_type, internal_entry, detail::record_name_type_hash>;

public:
    explicit record_cache(cache_options opts = {})
        : m_options(std::move(opts))
    {
        if(auto ec = validate(); ec)
            throw std::system_error(ec);
    }

    record_cache(cache_options opts, std::error_code &ec)
        : m_options(std::move(opts))
    {
        ec = validate();
        if(ec)
            m_options.goodbye_grace = std::chrono::seconds(1);
    }

    ~record_cache() = default;

    record_cache(const record_cache &) = delete;
    record_cache &operator=(const record_cache &) = delete;
    record_cache(record_cache &&) = delete;
    record_cache &operator=(record_cache &&) = delete;

    void insert(mdns_record_variant rec, endpoint origin)
    {
        auto key = detail::extract_name_type(rec);
        auto flush = detail::extract_cache_flush(rec);
        auto effective_ttl = detail::retained_ttl(detail::extract_ttl(rec), m_options.goodbye_grace);

        std::unique_lock lock(m_mutex);

        auto flush_origin = origin;

        if (!detail::refresh_match(m_entries.equal_range(key), rec, origin, flush, effective_ttl, Clock::now()))
        {
            m_entries.emplace(key, internal_entry{
                .record = std::move(rec),
                .origin = std::move(origin),
                .cache_flush = flush,
                .wire_ttl = effective_ttl,
                .inserted_at = Clock::now(),
            });
        }

        // RFC 6762 section 10.2: cache-flush handling
        if (flush)
            apply_cache_flush(key, flush_origin, lock);
    }

    std::vector<cache_entry> find(dns_name name, dns_type type, dns_class rclass = dns_class::in) const
    {
        std::shared_lock lock(m_mutex);

        auto now = Clock::now();
        std::vector<cache_entry> result;

        auto key = key_type{std::move(name), type, rclass};
        auto [it, end] = m_entries.equal_range(key);
        for (; it != end; ++it)
            result.push_back(detail::to_cache_entry(it->second, now));

        return result;
    }

    std::vector<cache_entry> snapshot() const
    {
        std::shared_lock lock(m_mutex);

        auto now = Clock::now();
        std::vector<cache_entry> result;
        result.reserve(m_entries.size());

        for (const auto &[key, entry] : m_entries)
            result.push_back(detail::to_cache_entry(entry, now));

        return result;
    }

    std::vector<cache_entry> erase_expired()
    {
        std::unique_lock lock(m_mutex);

        auto expired = detail::take_expired(m_entries, Clock::now());

        lock.unlock();

        if (!expired.empty() && m_options.on_expired)
        {
            auto callback_copy = expired;
            m_options.on_expired(std::move(callback_copy));
        }

        return expired;
    }

private:
    cache_options m_options;
    map_type m_entries;
    mutable std::shared_mutex m_mutex;

    std::error_code validate() const noexcept
    {
        if(m_options.goodbye_grace.count() <= 0)
            return std::make_error_code(std::errc::invalid_argument);
        return {};
    }

    void apply_cache_flush(const key_type &key, const endpoint &origin, std::unique_lock<std::shared_mutex> &lock)
    {
        auto range = m_entries.equal_range(key);
        auto marks = detail::mark_cache_flush(range, origin, Clock::now(), m_options.goodbye_grace);
        if (!marks.affected.empty() && m_options.on_cache_flush)
        {
            lock.unlock();
            m_options.on_cache_flush(marks.authoritative, std::move(marks.affected));
            lock.lock();
        }
    }
};

}

#endif
