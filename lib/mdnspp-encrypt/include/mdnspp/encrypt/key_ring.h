#ifndef HPP_GUARD_MDNSPP_ENCRYPT_KEY_RING_H
#define HPP_GUARD_MDNSPP_ENCRYPT_KEY_RING_H

#include "mdnspp/encrypt/aead.h"
#include "mdnspp/encrypt/secure_key.h"
#include "mdnspp/encrypt/encrypt_options.h"

#include <span>
#include <array>
#include <mutex>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <algorithm>

namespace mdnspp::encrypt {

struct key_copy
{
    std::array<std::byte, 32> bytes;

    explicit key_copy(const std::array<std::byte, 32> &source)
        : bytes(source)
    {
    }

    key_copy(const key_copy &other)
        : bytes(other.bytes)
    {
    }

    key_copy &operator=(const key_copy &) = delete;

    ~key_copy()
    {
        secure_zero(bytes.data(), bytes.size());
    }

    std::span<const std::byte, 32> span() const noexcept { return bytes; }
};

struct send_key
{
    key_copy key;
    uint32_t epoch;
};

struct receive_key
{
    key_copy key;
    bool is_previous;
};

class key_ring
{
    struct grace_state
    {
        std::optional<std::chrono::nanoseconds> duration;
        std::optional<uint64_t> packet_count;
        std::chrono::steady_clock::time_point started_at;
        uint64_t packets_seen;
        bool active;

        grace_state()
            : duration()
            , packet_count()
            , started_at()
            , packets_seen(0)
            , active(false)
        {
        }

        void start(const grace_period &gp)
        {
            duration = gp.duration;
            packet_count = gp.packet_count;
            started_at = std::chrono::steady_clock::now();
            packets_seen = 0;
            active = true;
        }

        bool expired() const noexcept
        {
            if(!active)
                return true;
            if(duration.has_value() && std::chrono::steady_clock::now() - started_at >= *duration)
                return true;
            return packet_count.has_value() && packets_seen >= *packet_count;
        }
    };

public:
    static constexpr std::chrono::seconds default_grace_duration{30};

    key_ring()
        : m_mutex()
        , m_key{}
        , m_prev_key{}
        , m_has_prev_key(false)
        , m_epoch(0)
        , m_grace()
    {
    }

    key_ring(std::span<const std::byte, 32> key, uint32_t epoch)
        : key_ring()
    {
        std::ranges::copy(key, m_key.begin());
        m_epoch = epoch;
    }

    key_ring(const key_ring &) = delete;
    key_ring &operator=(const key_ring &) = delete;

    ~key_ring()
    {
        secure_zero(m_key.data(), m_key.size());
        secure_zero(m_prev_key.data(), m_prev_key.size());
    }

    void update(secure_key new_psk, grace_period gp)
    {
        if(!gp.duration.has_value() && !gp.packet_count.has_value())
            gp.duration = default_grace_duration;

        std::lock_guard lock(m_mutex);
        m_prev_key = m_key;
        m_has_prev_key = true;
        std::ranges::copy(new_psk.bytes(), m_key.begin());
        ++m_epoch;
        m_grace.start(gp);
    }

    send_key key_for_send()
    {
        std::lock_guard lock(m_mutex);
        return send_key{key_copy(m_key), m_epoch};
    }

    // An epoch one ahead is tried with the current key: a peer whose epoch
    // counter runs one ahead under the same key (initial-epoch skew) is
    // accepted. A mismatched key fails authentication.
    std::optional<receive_key> key_for_epoch(uint32_t epoch)
    {
        std::lock_guard lock(m_mutex);
        expire_grace_locked();
        if(epoch == m_epoch || epoch == m_epoch + 1)
            return receive_key{key_copy(m_key), false};
        if(m_has_prev_key && epoch == m_epoch - 1)
            return receive_key{key_copy(m_prev_key), true};
        return std::nullopt;
    }

    void note_previous_key_packet()
    {
        std::lock_guard lock(m_mutex);
        ++m_grace.packets_seen;
    }

private:
    mutable std::mutex m_mutex;
    std::array<std::byte, 32> m_key;
    std::array<std::byte, 32> m_prev_key;
    bool m_has_prev_key;
    uint32_t m_epoch;
    grace_state m_grace;

    // Zeroizes the previous key as soon as the grace period has expired
    // instead of retaining it until destruction. Caller holds m_mutex.
    void expire_grace_locked() noexcept
    {
        if(!m_has_prev_key || !m_grace.expired())
            return;
        secure_zero(m_prev_key.data(), m_prev_key.size());
        m_has_prev_key = false;
        m_grace.active = false;
    }
};

}

#endif
