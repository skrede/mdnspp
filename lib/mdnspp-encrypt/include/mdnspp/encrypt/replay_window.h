#ifndef HPP_GUARD_MDNSPP_ENCRYPT_REPLAY_WINDOW_H
#define HPP_GUARD_MDNSPP_ENCRYPT_REPLAY_WINDOW_H

#include "mdnspp/encrypt/encrypt_error.h"

#include <list>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <unordered_map>

namespace mdnspp::encrypt {

// Anti-replay state per (sender_id, session_id) pair. A sender keeps at most
// max_sessions_per_sender independent windows; an unseen session opens a fresh
// window and, when the sender is full, replaces its least recently used one. No
// window is ever reset by a packet, so a captured packet of a tracked session is
// accepted at most once. A packet of a session that has been evicted (or that
// this window never saw) is accepted once, which is the inherent residual of
// keeping no clock or persistent state.
class replay_window
{
    struct session_window
    {
        uint64_t session_id;
        uint64_t max_seq;
        std::vector<uint64_t> bitmap;  // bit i = (max_seq - i) seen

        explicit session_window(std::size_t words);

        void restart(uint64_t id, uint64_t sequence);
        std::optional<encrypt_error> admit(uint64_t sequence, uint64_t window_size);
    };

    struct sender_state
    {
        std::vector<session_window> sessions;  // front = most recently used
        std::list<uint32_t>::iterator lru_pos;
    };

public:
    // window_size selects the number of sequence-number slots tracked per
    // session; a value of 0 is invalid and is clamped to 1. Memory per tracked
    // session is ceil(window_size / 64) uint64_t words, so a sender costs at most
    // max_sessions_per_sender * ceil(window_size / 64) * 8 bytes: 64 bytes at the
    // defaults (64, 8), and 8 KiB per session at the maximum window of 65535.
    explicit replay_window(uint16_t window_size = 64, uint16_t max_senders = 256,
                           uint16_t max_sessions_per_sender = 8);

    // Check and record a sequence number for a sender's session. Returns
    // std::nullopt on accept, or encrypt_error::replay_detected if the sequence
    // was already seen or is too old. Call only for authenticated packets.
    std::optional<encrypt_error> check_and_record(uint32_t sender_id, uint64_t session_id, uint64_t sequence);

    // Reset all state.
    void reset();

private:
    uint16_t m_window_size;
    uint16_t m_max_senders;
    uint16_t m_max_sessions;
    std::size_t m_words;
    std::unordered_map<uint32_t, sender_state> m_senders;
    std::list<uint32_t> m_lru;  // front = oldest, back = most recent

    sender_state &sender_for(uint32_t sender_id);
    void open_session(std::vector<session_window> &sessions, uint64_t session_id, uint64_t sequence);
};

}

#endif
