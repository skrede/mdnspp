#ifndef HPP_GUARD_MDNSPP_ENCRYPT_KEY_RING_H
#define HPP_GUARD_MDNSPP_ENCRYPT_KEY_RING_H

#include "mdnspp/encrypt/aead.h"
#include "mdnspp/encrypt/key_copy.h"
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
#include <system_error>

namespace mdnspp::encrypt {

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
        , m_keyed(false)
        , m_epoch(0)
        , m_grace()
    {
    }

    key_ring(std::span<const std::byte, 32> key, uint32_t epoch)
        : m_mutex()
        , m_key{}
        , m_prev_key{}
        , m_has_prev_key(false)
        , m_keyed(true)
        , m_epoch(epoch)
        , m_grace()
    {
        std::ranges::copy(key, m_key.begin());
    }

    key_ring(const key_ring &) = delete;
    key_ring &operator=(const key_ring &) = delete;

    ~key_ring()
    {
        secure_zero(m_key.data(), m_key.size());
        secure_zero(m_prev_key.data(), m_prev_key.size());
    }

    static key_ring make(const encrypt_options &opts, bool keyed)
    {
        if(!keyed)
            return key_ring();
        return key_ring(opts.psk.bytes(), opts.initial_epoch);
    }

    std::error_code update(secure_key new_psk, grace_period gp)
    {
        if(!m_keyed)
            return std::make_error_code(std::errc::operation_not_permitted);
        if(new_psk.is_zero())
            return std::make_error_code(std::errc::invalid_argument);
        if(!gp.duration.has_value() && !gp.packet_count.has_value())
            gp.duration = default_grace_duration;

        std::lock_guard lock(m_mutex);
        m_prev_key = m_key;
        m_has_prev_key = true;
        std::ranges::copy(new_psk.bytes(), m_key.begin());
        ++m_epoch;
        m_grace.start(gp);
        return {};
    }

    bool has_key() const noexcept
    {
        return m_keyed;
    }

    bool has_previous_key() const
    {
        std::lock_guard lock(m_mutex);
        return m_has_prev_key;
    }

    std::optional<send_key> key_for_send()
    {
        std::lock_guard lock(m_mutex);
        expire_grace_locked();
        if(!m_keyed)
            return std::nullopt;
        return send_key{key_copy(m_key), m_epoch};
    }

    // The current key is also tried one epoch ahead, and one epoch behind while no previous key is held, so peers whose
    // initial epochs differ by one under the same key hear each other both ways; a peer that rotated fails the AEAD.
    std::optional<receive_key> key_for_epoch(uint32_t epoch)
    {
        std::lock_guard lock(m_mutex);
        expire_grace_locked();
        if(!m_keyed)
            return std::nullopt;
        if(m_has_prev_key && epoch == m_epoch - 1)
            return receive_key{key_copy(m_prev_key), true};
        if(epoch == m_epoch - 1 || epoch == m_epoch || epoch == m_epoch + 1)
            return receive_key{key_copy(m_key), false};
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
    const bool m_keyed;
    uint32_t m_epoch;
    grace_state m_grace;

    // Runs on every send and receive key lookup, so an expired previous key is zeroized at the next lookup, not at
    // destruction. Caller holds m_mutex.
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
