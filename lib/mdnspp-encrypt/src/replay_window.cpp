#include "mdnspp/encrypt/replay_window.h"

#include <algorithm>

namespace {

// Shift a multi-word bitmap left by `shift` bit positions (toward higher bit
// indices). Bit i of word w corresponds to overall position w * 64 + i.
void shift_left(std::vector<uint64_t> &bitmap, uint64_t shift)
{
    const std::size_t words = bitmap.size();
    if(shift >= words * 64)
    {
        std::ranges::fill(bitmap, uint64_t{0});
        return;
    }

    const auto word_shift = static_cast<std::size_t>(shift / 64);
    const auto bit_shift = static_cast<std::size_t>(shift % 64);

    for(std::size_t i = words; i-- > 0;)
    {
        uint64_t value = 0;
        if(i >= word_shift)
        {
            value = bitmap[i - word_shift] << bit_shift;
            if(bit_shift != 0 && i > word_shift)
                value |= bitmap[i - word_shift - 1] >> (64 - bit_shift);
        }
        bitmap[i] = value;
    }
}

}

namespace mdnspp::encrypt {

replay_window::session_window::session_window(std::size_t words)
    : session_id(0)
    , max_seq(0)
    , bitmap(words, uint64_t{0})
{
}

void replay_window::session_window::restart(uint64_t id, uint64_t sequence)
{
    session_id = id;
    max_seq = sequence;
    std::ranges::fill(bitmap, uint64_t{0});
    bitmap[0] = 1;
}

std::optional<encrypt_error> replay_window::session_window::admit(uint64_t sequence, uint64_t window_size)
{
    if(sequence > max_seq)
    {
        shift_left(bitmap, sequence - max_seq);
        bitmap[0] |= uint64_t{1};
        max_seq = sequence;
        return std::nullopt;
    }

    const uint64_t diff = max_seq - sequence;
    if(diff >= window_size)
        return encrypt_error::replay_detected;

    const auto word = static_cast<std::size_t>(diff / 64);
    const uint64_t mask = uint64_t{1} << (diff % 64);
    if(bitmap[word] & mask)
        return encrypt_error::replay_detected;

    bitmap[word] |= mask;
    return std::nullopt;
}

replay_window::replay_window(uint16_t window_size, uint16_t max_senders, uint16_t max_sessions_per_sender)
    : m_window_size(window_size == 0 ? uint16_t{1} : window_size)
    , m_max_senders(max_senders)
    , m_max_sessions(max_sessions_per_sender == 0 ? uint16_t{1} : max_sessions_per_sender)
    , m_words((static_cast<std::size_t>(m_window_size) + 63) / 64)
{
}

std::optional<encrypt_error> replay_window::check_and_record(uint32_t sender_id, uint64_t session_id,
                                                             uint64_t sequence)
{
    auto &sessions = sender_for(sender_id).sessions;
    const auto found = std::ranges::find(sessions, session_id, &session_window::session_id);
    if(found == sessions.end())
    {
        open_session(sessions, session_id, sequence);
        return std::nullopt;
    }
    std::rotate(sessions.begin(), found, found + 1);
    return sessions.front().admit(sequence, m_window_size);
}

void replay_window::reset()
{
    m_senders.clear();
    m_lru.clear();
}

replay_window::sender_state &replay_window::sender_for(uint32_t sender_id)
{
    auto it = m_senders.find(sender_id);
    if(it != m_senders.end())
    {
        m_lru.splice(m_lru.end(), m_lru, it->second.lru_pos);
        return it->second;
    }

    if(m_max_senders > 0 && m_senders.size() >= static_cast<std::size_t>(m_max_senders))
    {
        m_senders.erase(m_lru.front());
        m_lru.pop_front();
    }
    m_lru.push_back(sender_id);
    return m_senders.emplace(sender_id, sender_state{{}, std::prev(m_lru.end())}).first->second;
}

void replay_window::open_session(std::vector<session_window> &sessions, uint64_t session_id, uint64_t sequence)
{
    if(sessions.size() < m_max_sessions)
        sessions.emplace_back(m_words);
    std::rotate(sessions.begin(), sessions.end() - 1, sessions.end());
    sessions.front().restart(session_id, sequence);
}

}
