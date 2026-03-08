#ifndef HPP_GUARD_MDNSPP_SERVER_PROBE_ANNOUNCE_H
#define HPP_GUARD_MDNSPP_SERVER_PROBE_ANNOUNCE_H

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
    unsigned probe_count{0};
    unsigned announce_count{0};
    unsigned conflict_attempt{0};
    uint16_t probe_id{0}; // random ID written into our probe queries to filter loopback
};

inline bool should_send_probe(const probe_announce_state &s)
{
    return s.state == server_state::probing && s.probe_count < 3;
}

inline bool probing_complete(const probe_announce_state &s)
{
    return s.state == server_state::probing && s.probe_count >= 3;
}

inline bool advance_probe(probe_announce_state &s)
{
    ++s.probe_count;
    return s.probe_count < 3;
}

inline bool should_send_announce(const probe_announce_state &s, unsigned max_count)
{
    return s.state == server_state::announcing && s.announce_count < max_count;
}

inline bool advance_announce(probe_announce_state &s, unsigned max_count)
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

}

#endif
