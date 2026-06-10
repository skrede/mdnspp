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

class replay_window
{
public:
    // A sequence number more than restart_threshold below a sender's recorded
    // maximum is interpreted as a sender restart (or a wrap of the 64-bit
    // sequence space) rather than a replay: the sender's window is
    // re-initialized at the new position and the packet is accepted.
    // The threshold (2^39) sits between the largest configurable window
    // (65535) and the spacing of randomized per-boot sequence starts (2^40,
    // see random_sequence_start() in aead.h), so genuine restarts always
    // exceed it while in-window reordering never does. Consequence: packets
    // recorded more than restart_threshold sequence numbers in the past
    // (in practice, packets from an earlier boot of the sender) can be
    // replayed; anti-replay guarantees hold within a single sender session.
    static constexpr uint64_t restart_threshold = uint64_t{1} << 39;

    // window_size selects the number of sequence-number slots tracked per
    // sender; a value of 0 is invalid and is clamped to 1. Memory per tracked
    // sender grows with the window: ceil(window_size / 64) uint64_t words,
    // i.e. 8 bytes at the default of 64 and 8 KiB at the maximum of 65535
    // (about 2 MiB across the default max_senders of 256).
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
        std::vector<uint64_t> bitmap;  // bit i = (max_seq - i) seen
        bool initialized{false};
    };

    uint16_t m_window_size;
    uint16_t m_max_senders;
    std::size_t m_words;
    std::unordered_map<uint32_t, window_state> m_windows;
    std::list<uint32_t> m_lru;  // front = oldest, back = most recent
    std::unordered_map<uint32_t, std::list<uint32_t>::iterator> m_lru_index;

    window_state &get_or_create(uint32_t sender_id);
    void touch_lru(uint32_t sender_id);
    void evict_oldest();
};

}

#endif
