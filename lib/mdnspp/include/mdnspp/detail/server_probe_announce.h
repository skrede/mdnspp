#ifndef HPP_GUARD_MDNSPP_SERVER_PROBE_ANNOUNCE_H
#define HPP_GUARD_MDNSPP_SERVER_PROBE_ANNOUNCE_H

#include <span>
#include <cstddef>
#include <cstdint>
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
    unsigned probe_count{0};
    unsigned announce_count{0};
    unsigned conflict_attempt{0};
    uint16_t probe_id{0}; // random ID written into our probe queries to filter loopback
};

inline bool should_send_probe(const probe_announce_state &s, unsigned max_count = 3)
{
    return s.state == server_state::probing && s.probe_count < max_count;
}

inline bool probing_complete(const probe_announce_state &s, unsigned max_count = 3)
{
    return s.state == server_state::probing && s.probe_count >= max_count;
}

inline bool advance_probe(probe_announce_state &s, unsigned max_count = 3)
{
    ++s.probe_count;
    return s.probe_count < max_count;
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

// Lexicographically compare two raw SRV rdata byte spans.
// Returns < 0 if ours < theirs, 0 if equal, > 0 if ours > theirs.
// Used for simultaneous-probe tiebreaking per RFC 6762 section 8.2.
inline int compare_authority_records(std::span<const std::byte> our_rdata,
                                     std::span<const std::byte> their_rdata)
{
    auto min_size = std::min(our_rdata.size(), their_rdata.size());
    for(std::size_t i = 0; i < min_size; ++i)
    {
        auto a = std::to_integer<uint8_t>(our_rdata[i]);
        auto b = std::to_integer<uint8_t>(their_rdata[i]);
        if(a != b)
            return static_cast<int>(a) - static_cast<int>(b);
    }
    if(our_rdata.size() < their_rdata.size()) return -1;
    if(our_rdata.size() > their_rdata.size()) return  1;
    return 0;
}

}

#endif
