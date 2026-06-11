#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_PROBE_ANNOUNCE_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_PROBE_ANNOUNCE_H

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"

#include <span>
#include <deque>
#include <chrono>
#include <vector>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <algorithm>

namespace mdnspp::detail {

enum class server_state : uint8_t
{
    idle,
    probing,
    announcing,
    live,
    stopped,
};

struct probe_announce_state
{
    server_state state{server_state::idle};
    uint8_t probe_count{0};
    uint8_t announce_count{0};
    uint32_t conflict_attempt{0};
};

inline bool should_send_probe(const probe_announce_state &s, uint8_t max_count = 3)
{
    return s.state == server_state::probing && s.probe_count < max_count;
}

inline bool probing_complete(const probe_announce_state &s, uint8_t max_count = 3)
{
    return s.state == server_state::probing && s.probe_count >= max_count;
}

inline bool advance_probe(probe_announce_state &s, uint8_t max_count = 3)
{
    ++s.probe_count;
    return s.probe_count < max_count;
}

inline bool should_send_announce(const probe_announce_state &s, uint8_t max_count)
{
    return s.state == server_state::announcing && s.announce_count < max_count;
}

inline bool advance_announce(probe_announce_state &s, uint8_t max_count)
{
    ++s.announce_count;
    return s.announce_count < max_count;
}

inline void begin_probing(probe_announce_state &s)
{
    s.state = server_state::probing;
    s.probe_count = 0;
}

inline void begin_announcing(probe_announce_state &s)
{
    s.state = server_state::announcing;
    s.announce_count = 0;
}

// One record of a proposed record set in DNS uncompressed form, ordered by
// class, then type, then raw rdata bytes (RFC 6762 §8.2.1).
struct tiebreak_record
{
    uint16_t rclass{1};
    uint16_t rtype{0};
    std::vector<std::byte> rdata;

    friend auto operator<=>(const tiebreak_record &, const tiebreak_record &) = default;
};

// Extracts the Authority-section records of a probe query in uncompressed
// form. Name-containing rdata (SRV target, PTR target) is decompressed and
// re-encoded so the comparison operates on canonical uncompressed bytes
// (RFC 6762 §8.2.1). The cache-flush bit is cleared from the class.
inline std::vector<tiebreak_record> extract_authority_records(std::span<const std::byte> data)
{
    if(data.size() < 12)
        return {};

    uint16_t qdcount = read_u16_be(data.data() + 4);
    uint16_t ancount = read_u16_be(data.data() + 6);
    uint16_t nscount = read_u16_be(data.data() + 8);

    if(nscount == 0)
        return {};

    std::size_t offset = 12;

    for(uint16_t i = 0; i < qdcount; ++i)
    {
        if(!skip_dns_name(data, offset)) return {};
        if(offset + 4 > data.size()) return {};
        offset += 4;
    }

    for(uint16_t i = 0; i < ancount; ++i)
    {
        if(!skip_dns_name(data, offset)) return {};
        if(offset + 10 > data.size()) return {};
        offset += 8;
        uint16_t rdlen = read_u16_be(data.data() + offset);
        offset += 2;
        if(offset + rdlen > data.size()) return {};
        offset += rdlen;
    }

    std::vector<tiebreak_record> records;
    records.reserve(nscount);

    for(uint16_t i = 0; i < nscount; ++i)
    {
        if(!skip_dns_name(data, offset)) return {};
        if(offset + 10 > data.size()) return {};
        uint16_t rtype = read_u16_be(data.data() + offset);
        uint16_t rclass = static_cast<uint16_t>(read_u16_be(data.data() + offset + 2) & 0x7FFFu);
        offset += 8;
        uint16_t rdlen = read_u16_be(data.data() + offset);
        offset += 2;
        if(offset + rdlen > data.size()) return {};

        std::vector<std::byte> rdata;
        if(rtype == to_underlying(dns_type::srv) && rdlen >= 6)
        {
            rdata.assign(data.data() + offset, data.data() + offset + 6);
            auto target = read_dns_name(data, offset + 6);
            if(!target.has_value()) return {};
            auto encoded = encode_dns_name(*target);
            if(!encoded.has_value()) return {};
            rdata.insert(rdata.end(), encoded->begin(), encoded->end());
        }
        else if(rtype == to_underlying(dns_type::ptr))
        {
            auto target = read_dns_name(data, offset);
            if(!target.has_value()) return {};
            auto encoded = encode_dns_name(*target);
            if(!encoded.has_value()) return {};
            rdata = std::move(*encoded);
        }
        else
        {
            rdata.assign(data.data() + offset, data.data() + offset + rdlen);
        }

        records.push_back(tiebreak_record{rclass, rtype, std::move(rdata)});
        offset += rdlen;
    }

    return records;
}

// RFC 6762 §8.2.1 simultaneous-probe tiebreak over full record sets: both
// sets are sorted (class, type, rdata) and compared pairwise; if one set is a
// prefix of the other, the set with records remaining wins. Returns < 0 when
// ours loses, 0 on an exact tie (identical data — NOT a conflict), > 0 when
// ours wins.
inline int32_t compare_record_sets(std::vector<tiebreak_record> ours,
                                   std::vector<tiebreak_record> theirs)
{
    std::sort(ours.begin(), ours.end());
    std::sort(theirs.begin(), theirs.end());

    auto count = (std::min)(ours.size(), theirs.size());
    for(std::size_t i = 0; i < count; ++i)
    {
        auto cmp = ours[i] <=> theirs[i];
        if(cmp < 0) return -1;
        if(cmp > 0) return 1;
    }
    if(ours.size() < theirs.size()) return -1;
    if(ours.size() > theirs.size()) return 1;
    return 0;
}

// RFC 6762 §8.1 probe rate limiting: on 15 or more conflicts within a
// ten-second window, every subsequent probe attempt must wait at least five
// seconds. The throttle stays engaged until the window drains of conflicts.
template <typename Clock = std::chrono::steady_clock>
class probe_rate_limiter
{
public:
    using time_point = typename Clock::time_point;

    static constexpr std::size_t conflict_threshold{15};
    static constexpr std::chrono::seconds conflict_window{10};
    static constexpr std::chrono::seconds probe_delay{5};

    void record_conflict()
    {
        auto now = Clock::now();
        m_conflicts.push_back(now);
        prune(now);
    }

    [[nodiscard]] bool throttled()
    {
        prune(Clock::now());
        if(m_conflicts.size() >= conflict_threshold)
            m_engaged = true;
        else if(m_conflicts.empty())
            m_engaged = false;
        return m_engaged;
    }

    void reset()
    {
        m_conflicts.clear();
        m_engaged = false;
    }

private:
    void prune(time_point now)
    {
        while(!m_conflicts.empty() && now - m_conflicts.front() > conflict_window)
            m_conflicts.pop_front();
    }

    std::deque<time_point> m_conflicts;
    bool m_engaged{false};
};

}

#endif
