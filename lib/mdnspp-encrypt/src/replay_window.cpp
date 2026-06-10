#include "mdnspp/encrypt/replay_window.h"

namespace mdnspp::encrypt {

replay_window::replay_window(uint16_t window_size, uint16_t max_senders)
    : m_window_size(window_size)
    , m_max_senders(max_senders)
{
}

std::optional<encrypt_error> replay_window::check_and_record(uint32_t sender_id, uint64_t sequence)
{
    window_state &ws = get_or_create(sender_id);
    touch_lru(sender_id);

    if (!ws.initialized)
    {
        ws.max_seq     = sequence;
        ws.bitmap      = 1;
        ws.initialized = true;
        return std::nullopt;
    }

    if (sequence > ws.max_seq)
    {
        // Advance the window.
        // Semantics: bit i means (max_seq - i) has been seen.
        // When max_seq increases by `shift`, old bit i moves to bit (i + shift).
        // Left-shift preserves older entries at higher bit positions.
        uint64_t shift = sequence - ws.max_seq;
        if (shift >= 64)
            ws.bitmap = 0;
        else
            ws.bitmap <<= shift;
        ws.bitmap |= uint64_t{1};
        ws.max_seq = sequence;
        return std::nullopt;
    }

    if (sequence == ws.max_seq)
    {
        // bit 0 is always set for max_seq
        return encrypt_error::replay_detected;
    }

    // sequence < max_seq
    uint64_t diff = ws.max_seq - sequence;
    if (diff >= static_cast<uint64_t>(m_window_size))
        return encrypt_error::replay_detected;

    // Within window: check bit at position diff
    uint64_t mask = uint64_t{1} << diff;
    if (ws.bitmap & mask)
        return encrypt_error::replay_detected;

    ws.bitmap |= mask;
    return std::nullopt;
}

void replay_window::reset()
{
    m_windows.clear();
    m_lru.clear();
    m_lru_index.clear();
}

replay_window::window_state &replay_window::get_or_create(uint32_t sender_id)
{
    auto it = m_windows.find(sender_id);
    if (it != m_windows.end())
        return it->second;

    if (m_max_senders > 0 && m_windows.size() >= static_cast<size_t>(m_max_senders))
        evict_oldest();

    auto [inserted_it, ok] = m_windows.emplace(sender_id, window_state{});
    m_lru.push_back(sender_id);
    m_lru_index.emplace(sender_id, std::prev(m_lru.end()));
    return inserted_it->second;
}

void replay_window::touch_lru(uint32_t sender_id)
{
    auto index_it = m_lru_index.find(sender_id);
    if (index_it == m_lru_index.end())
        return;

    m_lru.splice(m_lru.end(), m_lru, index_it->second);
}

void replay_window::evict_oldest()
{
    if (m_lru.empty())
        return;

    uint32_t oldest = m_lru.front();
    m_lru.pop_front();
    m_lru_index.erase(oldest);
    m_windows.erase(oldest);
}

}
