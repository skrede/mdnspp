#ifndef HPP_GUARD_MDNSPP_ENCRYPT_REPLAY_WINDOW_H
#define HPP_GUARD_MDNSPP_ENCRYPT_REPLAY_WINDOW_H

#include "mdnspp/encrypt/encrypt_error.h"

#include <list>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <system_error>
#include <unordered_map>

namespace mdnspp::encrypt {

// No window is ever reset by a packet, so a captured packet of a tracked session is accepted at most once; a packet
// of an untracked session is accepted once, the residual of keeping no clock or persistent state.
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

    struct checked
    {
    };

public:
    explicit replay_window(uint16_t window_size = 64, uint16_t max_senders = 256,
                           uint16_t max_sessions_per_sender = 8);

    replay_window(uint16_t window_size, uint16_t max_senders, uint16_t max_sessions_per_sender, std::error_code &ec);

    replay_window(const replay_window &) = delete;
    replay_window &operator=(const replay_window &) = delete;

    // Only for authenticated packets: a forged sequence number would advance the window.
    std::optional<encrypt_error> check_and_record(uint32_t sender_id, uint64_t session_id, uint64_t sequence);

    void reset();

private:
    uint16_t m_window_size;
    uint16_t m_max_senders;
    uint16_t m_max_sessions;
    std::size_t m_words;
    std::unordered_map<uint32_t, sender_state> m_senders;
    std::list<uint32_t> m_lru;  // front = oldest, back = most recent

    replay_window(checked, uint16_t window_size, uint16_t max_senders, uint16_t max_sessions_per_sender,
                  std::error_code ec);

    sender_state &sender_for(uint32_t sender_id);
    void open_session(std::vector<session_window> &sessions, uint64_t session_id, uint64_t sequence);
};

}

#endif
