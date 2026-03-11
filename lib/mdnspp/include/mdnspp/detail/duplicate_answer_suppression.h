#ifndef HPP_GUARD_MDNSPP_DUPLICATE_ANSWER_SUPPRESSION_H
#define HPP_GUARD_MDNSPP_DUPLICATE_ANSWER_SUPPRESSION_H

#include "mdnspp/records.h"
#include "mdnspp/record_cache.h"

#include <vector>
#include <cstdint>

namespace mdnspp::detail {

struct seen_answer
{
    mdns_record_variant record;
    uint32_t observed_ttl{0};
};

struct duplicate_suppression_state
{
    void observe(const mdns_record_variant &rec, uint32_t ttl)
    {
        m_seen.push_back(seen_answer{rec, ttl});
    }

    // RFC 6762 section 7.4: suppress if an identical record was seen with
    // observed_ttl >= our_ttl (NOT the 50% rule from section 7.1).
    [[nodiscard]] bool is_suppressed(const mdns_record_variant &rec,
                                     uint32_t our_ttl) const noexcept
    {
        for (const auto &seen : m_seen)
        {
            if (record_identity_equal(seen.record, rec) &&
                seen.observed_ttl >= our_ttl)
            {
                return true;
            }
        }
        return false;
    }

    void reset() noexcept { m_seen.clear(); }

    [[nodiscard]] bool empty() const noexcept { return m_seen.empty(); }

private:
    std::vector<seen_answer> m_seen;
};

}

#endif
