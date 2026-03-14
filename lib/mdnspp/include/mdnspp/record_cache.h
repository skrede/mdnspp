#ifndef HPP_GUARD_MDNSPP_RECORD_CACHE_H
#define HPP_GUARD_MDNSPP_RECORD_CACHE_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/cache_entry.h"
#include "mdnspp/cache_options.h"

#include "mdnspp/detail/dns_enums.h"

#include <mutex>
#include <chrono>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <optional>
#include <functional>
#include <string_view>
#include <shared_mutex>
#include <unordered_map>

namespace mdnspp {
namespace detail {

struct record_name_type
{
    dns_name name;
    dns_type type{dns_type::none};

    bool operator==(const record_name_type &) const = default;
};

struct record_name_type_hash
{
    std::size_t operator()(const record_name_type &k) const noexcept
    {
        auto h1 = std::hash<dns_name>{}(k.name);
        auto h2 = std::hash<uint16_t>{}(std::to_underlying(k.type));
        return h1 ^ (h2 << 16);
    }
};

inline auto extract_name_type(const mdns_record_variant &rec) -> record_name_type
{
    return std::visit([](const auto &r) -> record_name_type {
        return {r.name, []<typename R>(const R &) {
            if constexpr (std::is_same_v<R, record_a>) return dns_type::a;
            else if constexpr (std::is_same_v<R, record_aaaa>) return dns_type::aaaa;
            else if constexpr (std::is_same_v<R, record_ptr>) return dns_type::ptr;
            else if constexpr (std::is_same_v<R, record_srv>) return dns_type::srv;
            else if constexpr (std::is_same_v<R, record_txt>) return dns_type::txt;
        }(r)};
    }, rec);
}

inline auto extract_class(const mdns_record_variant &rec) -> dns_class
{
    return std::visit([](const auto &r) { return r.rclass; }, rec);
}

inline auto extract_ttl(const mdns_record_variant &rec) -> uint32_t
{
    return std::visit([](const auto &r) { return r.ttl; }, rec);
}

inline auto extract_cache_flush(const mdns_record_variant &rec) -> bool
{
    return std::visit([](const auto &r) { return r.cache_flush; }, rec);
}

inline bool rdata_equal(const mdns_record_variant &a, const mdns_record_variant &b)
{
    if (a.index() != b.index())
        return false;

    return std::visit([](const auto &lhs, const auto &rhs) -> bool {
        using L = std::remove_cvref_t<decltype(lhs)>;
        using R = std::remove_cvref_t<decltype(rhs)>;

        if constexpr (!std::is_same_v<L, R>)
            return false;
        else if constexpr (std::is_same_v<L, record_a>)
            return lhs.address_string == rhs.address_string;
        else if constexpr (std::is_same_v<L, record_aaaa>)
            return lhs.address_string == rhs.address_string;
        else if constexpr (std::is_same_v<L, record_ptr>)
            return lhs.ptr_name == rhs.ptr_name;
        else if constexpr (std::is_same_v<L, record_srv>)
            return lhs.port == rhs.port &&
                   lhs.weight == rhs.weight &&
                   lhs.priority == rhs.priority &&
                   lhs.srv_name == rhs.srv_name;
        else if constexpr (std::is_same_v<L, record_txt>)
        {
            if (lhs.entries.size() != rhs.entries.size())
                return false;
            for (std::size_t i = 0; i < lhs.entries.size(); ++i)
            {
                if (lhs.entries[i].key != rhs.entries[i].key ||
                    lhs.entries[i].value != rhs.entries[i].value)
                    return false;
            }
            return true;
        }
        else
            return false;
    }, a, b);
}

inline bool record_identity_equal(const mdns_record_variant &a, const mdns_record_variant &b)
{
    auto ka = extract_name_type(a);
    auto kb = extract_name_type(b);
    return ka == kb &&
           extract_class(a) == extract_class(b) &&
           rdata_equal(a, b);
}

}

template <typename Clock = std::chrono::steady_clock>
class record_cache
{
    using time_point = typename Clock::time_point;

    struct internal_entry
    {
        mdns_record_variant record;
        endpoint origin;
        bool cache_flush{false};
        uint32_t wire_ttl{0};
        time_point inserted_at{};
        std::optional<time_point> flush_deadline{};
    };

    using key_type = detail::record_name_type;
    using map_type = std::unordered_multimap<key_type, internal_entry, detail::record_name_type_hash>;

public:
    explicit record_cache(cache_options opts = {})
        : m_options(std::move(opts))
    {
    }

    record_cache(const record_cache &) = delete;
    record_cache &operator=(const record_cache &) = delete;
    record_cache(record_cache &&) = delete;
    record_cache &operator=(record_cache &&) = delete;

    void insert(mdns_record_variant rec, endpoint origin)
    {
        auto key = detail::extract_name_type(rec);
        auto flush = detail::extract_cache_flush(rec);
        auto ttl = detail::extract_ttl(rec);

        // RFC 6762 section 10.1: goodbye record (TTL=0) retained for goodbye_grace seconds
        uint32_t effective_ttl = (ttl == 0) ? static_cast<uint32_t>(m_options.goodbye_grace.count()) : ttl;

        std::unique_lock lock(m_mutex);

        auto flush_origin = origin;

        auto [it, end] = m_entries.equal_range(key);
        bool found = false;
        for (; it != end; ++it)
        {
            if (detail::record_identity_equal(it->second.record, rec))
            {
                it->second.inserted_at = Clock::now();
                it->second.wire_ttl = effective_ttl;
                it->second.cache_flush = flush;
                it->second.origin = std::move(origin);
                it->second.flush_deadline.reset();
                found = true;
                break;
            }
        }

        if (!found)
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

    auto find(dns_name name, dns_type type) const -> std::vector<cache_entry>
    {
        std::shared_lock lock(m_mutex);

        auto now = Clock::now();
        std::vector<cache_entry> result;

        auto key = key_type{std::move(name), type};
        auto [it, end] = m_entries.equal_range(key);
        for (; it != end; ++it)
            result.push_back(to_cache_entry(it->second, now));

        return result;
    }

    auto snapshot() const -> std::vector<cache_entry>
    {
        std::shared_lock lock(m_mutex);

        auto now = Clock::now();
        std::vector<cache_entry> result;
        result.reserve(m_entries.size());

        for (const auto &[key, entry] : m_entries)
            result.push_back(to_cache_entry(entry, now));

        return result;
    }

    auto erase_expired() -> std::vector<cache_entry>
    {
        std::unique_lock lock(m_mutex);

        auto now = Clock::now();
        std::vector<cache_entry> expired;

        for (auto it = m_entries.begin(); it != m_entries.end(); )
        {
            if (is_expired(it->second, now))
            {
                expired.push_back(to_cache_entry(it->second, now));
                it = m_entries.erase(it);
            }
            else
            {
                ++it;
            }
        }

        lock.unlock();

        if (!expired.empty() && m_options.on_expired)
        {
            auto callback_copy = expired;
            m_options.on_expired(std::move(callback_copy));
        }

        return expired;
    }

private:
    void apply_cache_flush(const key_type &key, const endpoint &origin,
                           std::unique_lock<std::shared_mutex> &lock)
    {
        auto now = Clock::now();
        auto deadline = now + m_options.goodbye_grace;

        std::vector<cache_entry> affected;
        cache_entry authoritative;

        auto [it, end] = m_entries.equal_range(key);
        for (; it != end; ++it)
        {
            auto &entry = it->second;
            if (entry.origin == origin)
            {
                if (entry.cache_flush)
                    authoritative = to_cache_entry(entry, now);
            }
            else
            {
                if (!entry.flush_deadline || *entry.flush_deadline > deadline)
                    entry.flush_deadline = deadline;

                affected.push_back(to_cache_entry(entry, now));
            }
        }

        if (!affected.empty() && m_options.on_cache_flush)
        {
            lock.unlock();
            m_options.on_cache_flush(authoritative, std::move(affected));
            lock.lock();
        }
    }

    static bool is_expired(const internal_entry &e, time_point now)
    {
        if (now >= e.inserted_at + std::chrono::seconds(e.wire_ttl))
            return true;
        if (e.flush_deadline && now >= *e.flush_deadline)
            return true;
        return false;
    }

    static auto to_cache_entry(const internal_entry &e, time_point now) -> cache_entry
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

    cache_options m_options;
    map_type m_entries;
    mutable std::shared_mutex m_mutex;
};

}

#endif
