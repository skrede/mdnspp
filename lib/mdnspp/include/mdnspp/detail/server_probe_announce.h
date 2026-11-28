#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_PROBE_ANNOUNCE_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_PROBE_ANNOUNCE_H

#include "mdnspp/detail/server_tiebreak.h"

#include <deque>
#include <chrono>
#include <cstddef>
#include <cstdint>

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

// RFC 6762 §8.1: on 15 or more conflicts within ten seconds every further probe waits at least five seconds.
// The throttle stays engaged until the window holds no conflict.
template <typename Clock = std::chrono::steady_clock>
class probe_rate_limiter
{
public:
    using time_point = typename Clock::time_point;

    static constexpr std::size_t conflict_threshold{15};
    static constexpr std::chrono::seconds conflict_window{10};
    static constexpr std::chrono::seconds probe_delay{5};

    probe_rate_limiter()
        : m_conflicts()
        , m_engaged(false)
    {
    }

    void record_conflict()
    {
        auto now = Clock::now();
        m_conflicts.push_back(now);
        prune(now);
    }

    bool throttled()
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
    bool m_engaged;
};

}

#endif
