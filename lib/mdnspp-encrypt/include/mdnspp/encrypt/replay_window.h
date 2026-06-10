#ifndef HPP_GUARD_MDNSPP_ENCRYPT_REPLAY_WINDOW_H
#define HPP_GUARD_MDNSPP_ENCRYPT_REPLAY_WINDOW_H

#include "mdnspp/encrypt/encrypt_error.h"

#include <list>
#include <cstdint>
#include <optional>
#include <unordered_map>

namespace mdnspp::encrypt {

class replay_window
{
public:
    explicit replay_window(uint16_t window_size = 64, uint16_t max_senders = 256);

    // Check and record a sequence number for a given sender.
    // Returns std::nullopt on accept,
    // or encrypt_error::replay_detected if the sequence was already seen or is too old.
    std::optional<encrypt_error> check_and_record(uint32_t sender_id, uint64_t sequence);

    // Reset all state.
    void reset();

private:
    struct window_state
    {
        uint64_t max_seq{0};
        uint64_t bitmap{0};  // bit i = (max_seq - i) seen
        bool initialized{false};
    };

    uint16_t m_window_size;
    uint16_t m_max_senders;
    std::unordered_map<uint32_t, window_state> m_windows;
    std::list<uint32_t> m_lru;  // front = oldest, back = most recent
    std::unordered_map<uint32_t, std::list<uint32_t>::iterator> m_lru_index;

    window_state &get_or_create(uint32_t sender_id);
    void touch_lru(uint32_t sender_id);
    void evict_oldest();
};

}

#endif
