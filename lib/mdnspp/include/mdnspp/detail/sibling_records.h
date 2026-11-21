#ifndef HPP_GUARD_MDNSPP_DETAIL_SIBLING_RECORDS_H
#define HPP_GUARD_MDNSPP_DETAIL_SIBLING_RECORDS_H

#include "mdnspp/detail/server_record_match.h"

#include "mdnspp/records.h"
#include "mdnspp/service_info.h"

#include <map>
#include <mutex>
#include <memory>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <variant>
#include <optional>

namespace mdnspp::detail {

// RFC 6762 section 14: the per-NIC servers of one group may hear each other on one link, so a record another
// member publishes is not a conflict. Address records belong to the whole group (one host); SRV and TXT records
// only to members built from the same options element, so two elements claiming one instance name still conflict.
class sibling_records
{
    struct member
    {
        std::size_t element;
        std::optional<service_info> info;
    };

public:
    sibling_records()
        : m_next_id(0)
        , m_mutex()
        , m_members()
    {
    }

    uint64_t join(std::size_t element)
    {
        std::lock_guard lock(m_mutex);
        m_members.emplace(m_next_id, member{element, std::nullopt});
        return m_next_id++;
    }

    void publish(uint64_t id, service_info info)
    {
        std::lock_guard lock(m_mutex);
        if(auto it = m_members.find(id); it != m_members.end())
            it->second.info = std::move(info);
    }

    void leave(uint64_t id)
    {
        std::lock_guard lock(m_mutex);
        m_members.erase(id);
    }

    bool owns(uint64_t id, const mdns_record_variant &record) const
    {
        std::lock_guard lock(m_mutex);
        auto self = m_members.find(id);
        if(self == m_members.end())
            return false;
        bool group_wide = std::holds_alternative<record_a>(record) || std::holds_alternative<record_aaaa>(record);
        for(const auto &[other, m] : m_members)
        {
            if(other == id || !m.info.has_value())
                continue;
            if((group_wide || m.element == self->second.element) && record_matches_ours(record, *m.info))
                return true;
        }
        return false;
    }

private:
    uint64_t m_next_id;
    mutable std::mutex m_mutex;
    std::map<uint64_t, member> m_members;
};

class sibling_membership
{
public:
    sibling_membership(std::shared_ptr<sibling_records> registry, std::size_t element)
        : m_registry(std::move(registry))
        , m_id(m_registry ? m_registry->join(element) : 0)
    {
    }

    sibling_membership(const sibling_membership &) = delete;
    sibling_membership &operator=(const sibling_membership &) = delete;
    sibling_membership(sibling_membership &&) = delete;
    sibling_membership &operator=(sibling_membership &&) = delete;

    ~sibling_membership()
    {
        withdraw();
    }

    void publish(const service_info &info)
    {
        if(m_registry)
            m_registry->publish(m_id, info);
    }

    void withdraw()
    {
        if(m_registry)
            m_registry->leave(m_id);
    }

    bool owns(const mdns_record_variant &record) const
    {
        return m_registry && m_registry->owns(m_id, record);
    }

private:
    std::shared_ptr<sibling_records> m_registry;
    uint64_t m_id;
};

}

#endif
