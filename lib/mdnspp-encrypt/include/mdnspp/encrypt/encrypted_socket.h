#ifndef HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_SOCKET_H
#define HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_SOCKET_H

#include "mdnspp/policy.h"
#include "mdnspp/encrypt/aead.h"
#include "mdnspp/encrypt/replay_window.h"
#include "mdnspp/encrypt/packet_header.h"
#include "mdnspp/encrypt/encrypt_options.h"
#include "mdnspp/encrypt/encrypt_socket_options.h"

#include <span>
#include <array>
#include <mutex>
#include <atomic>
#include <chrono>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <optional>
#include <algorithm>
#include <system_error>

namespace mdnspp::encrypt {

// Thread-safety contract:
// - update_key() and send() may be called from any thread, concurrently with
//   each other and with the receive path; key, epoch, and grace-period state
//   are guarded by an internal mutex (key material is copied under the lock,
//   AEAD operations run outside it).
// - async_receive() arming and handler invocation follow the inner socket's
//   executor semantics; the per-sender replay window is confined to the
//   receive path and must not be touched from other threads.
template <socket_like InnerSocket>
class encrypted_socket
{
public:
    // Default duration bound applied by update_key() when the supplied
    // grace_period sets neither duration nor packet_count.
    static constexpr std::chrono::seconds default_grace_duration{30};

    // The executor-only constructors exist to satisfy the policy_like
    // constructibility requirements; a socket constructed without options
    // holds no key and must be discarded, not used.
    template <typename Executor>
        requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
    explicit encrypted_socket(Executor &&ex)
        : m_inner(std::forward<Executor>(ex))
    {
        init_crypto();
    }

    template <typename Executor>
        requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
    explicit encrypted_socket(Executor &&ex, std::error_code &ec)
        : m_inner(std::forward<Executor>(ex), ec)
    {
        init_crypto();
    }

    // Throws std::system_error with std::errc::invalid_argument if
    // opts.encrypt.validate() fails (zero sender_id, all-zero PSK, or zero
    // replay_window_size). Validation runs before the key is copied.
    template <typename Executor>
        requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
    explicit encrypted_socket(Executor &&ex, const encrypt_socket_options &opts)
        : m_inner(std::forward<Executor>(ex), static_cast<const socket_options &>(opts))
        , m_sender_id(opts.encrypt.sender_id)
        , m_replay(opts.encrypt.replay_window_size, opts.encrypt.max_senders)
        , m_accept_cleartext(opts.encrypt.accept_cleartext)
        , m_auth_only(opts.encrypt.auth_only)
        , m_detection(opts.encrypt.detection)
        , m_recv_mode(opts.encrypt.recv_mode)
        , m_epoch(opts.encrypt.initial_epoch)
    {
        init_crypto();
        if(auto ec = opts.encrypt.validate())
            throw std::system_error(ec, "mdnspp::encrypt: invalid encrypt_options");
        std::ranges::copy(opts.encrypt.psk.bytes(), m_key.begin());
    }

    // Sets ec to std::errc::invalid_argument if opts.encrypt.validate() fails;
    // the key is not copied in that case and the socket must not be used.
    template <typename Executor>
        requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
    explicit encrypted_socket(Executor &&ex, const encrypt_socket_options &opts, std::error_code &ec)
        : m_inner(std::forward<Executor>(ex), static_cast<const socket_options &>(opts), ec)
        , m_sender_id(opts.encrypt.sender_id)
        , m_replay(opts.encrypt.replay_window_size, opts.encrypt.max_senders)
        , m_accept_cleartext(opts.encrypt.accept_cleartext)
        , m_auth_only(opts.encrypt.auth_only)
        , m_detection(opts.encrypt.detection)
        , m_recv_mode(opts.encrypt.recv_mode)
        , m_epoch(opts.encrypt.initial_epoch)
    {
        init_crypto();
        if(ec)
            return;
        ec = opts.encrypt.validate();
        if(ec)
            return;
        std::ranges::copy(opts.encrypt.psk.bytes(), m_key.begin());
    }

    encrypted_socket(const encrypted_socket &) = delete;
    encrypted_socket &operator=(const encrypted_socket &) = delete;
    encrypted_socket(encrypted_socket &&) = delete;
    encrypted_socket &operator=(encrypted_socket &&) = delete;

    ~encrypted_socket()
    {
        secure_zero(m_key.data(), m_key.size());
        secure_zero(m_prev_key.data(), m_prev_key.size());
    }

    void close()
    {
        m_inner.close();
    }

    void send(const endpoint &dest, std::span<const std::byte> plaintext)
    {
        auto packet = build_encrypted_packet(plaintext);
        m_inner.send(dest, std::span<const std::byte>(packet));
    }

    void send(const endpoint &dest, std::span<const std::byte> plaintext, std::error_code &ec)
    {
        auto packet = build_encrypted_packet(plaintext);
        m_inner.send(dest, std::span<const std::byte>(packet), ec);
    }

    void async_receive(
        move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)> handler)
    {
        m_inner.async_receive(
            [this, h = std::move(handler)](std::error_code ec, const recv_metadata &meta,
                                           std::span<std::byte> raw) mutable
            {
                if(ec)
                {
                    h(ec, meta, raw);
                    return;
                }
                handle_received(meta, raw, h);
            });
    }

    // Rotate the PSK. Thread-safe (see class contract). The current key
    // becomes the previous key and remains accepted for packets stamped with
    // the previous epoch until the grace period expires, at which point the
    // previous key is zeroized. If gp sets neither duration nor packet_count,
    // a duration bound of default_grace_duration is applied.
    void update_key(secure_key new_psk, grace_period gp)
    {
        if(!gp.duration.has_value() && !gp.packet_count.has_value())
            gp.duration = default_grace_duration;

        std::lock_guard lock(m_key_mutex);

        m_prev_key = m_key;
        m_has_prev_key = true;

        std::ranges::copy(new_psk.bytes(), m_key.begin());

        ++m_epoch;

        m_grace.duration     = gp.duration;
        m_grace.packet_count = gp.packet_count;
        m_grace.started_at   = std::chrono::steady_clock::now();
        m_grace.packets_seen = 0;
        m_grace.active       = true;
    }

    InnerSocket &inner() noexcept { return m_inner; }
    const InnerSocket &inner() const noexcept { return m_inner; }

private:
    struct grace_period_state
    {
        std::optional<std::chrono::nanoseconds> duration;
        std::optional<uint64_t>                 packet_count;
        std::chrono::steady_clock::time_point   started_at{};
        uint64_t                                packets_seen{0};
        bool                                    active{false};
    };

    InnerSocket m_inner;
    uint32_t m_sender_id{0};
    std::atomic<uint64_t> m_seq_counter{random_sequence_start()};
    replay_window m_replay;
    bool m_accept_cleartext{false};
    bool m_auth_only{false};
    cleartext_detection m_detection{cleartext_detection::magic_byte};
    receive_mode m_recv_mode{receive_mode::accept_both};

    // Guards m_key, m_prev_key, m_has_prev_key, m_epoch, and m_grace.
    mutable std::mutex m_key_mutex;
    std::array<std::byte, 32> m_key{};
    std::array<std::byte, 32> m_prev_key{};
    bool m_has_prev_key{false};
    uint32_t m_epoch{0};
    grace_period_state m_grace{};

    // Caller must hold m_key_mutex.
    bool is_grace_expired() const noexcept
    {
        if (!m_grace.active)
            return true;

        if (m_grace.duration.has_value())
        {
            auto elapsed = std::chrono::steady_clock::now() - m_grace.started_at;
            if (elapsed >= *m_grace.duration)
                return true;
        }
        if (m_grace.packet_count.has_value())
        {
            if (m_grace.packets_seen >= *m_grace.packet_count)
                return true;
        }
        return false;
    }

    // Caller must hold m_key_mutex. Zeroizes the previous key as soon as the
    // grace period has expired, rather than retaining it until destruction.
    void expire_grace_locked() noexcept
    {
        if(m_has_prev_key && is_grace_expired())
        {
            secure_zero(m_prev_key.data(), m_prev_key.size());
            m_has_prev_key = false;
            m_grace.active = false;
        }
    }

    std::vector<std::byte> build_encrypted_packet(std::span<const std::byte> plaintext)
    {
        encrypted_packet_header hdr;
        hdr.sender_id = m_sender_id;
        hdr.sequence  = m_seq_counter.fetch_add(1, std::memory_order_relaxed) + 1;
        hdr.flags     = m_auth_only ? uint8_t{0} : flag_encrypted;

        std::array<std::byte, 32> key_copy;
        {
            std::lock_guard lock(m_key_mutex);
            hdr.epoch = m_epoch;
            key_copy  = m_key;
        }
        auto packet = aead_encrypt(std::span<const std::byte, 32>(key_copy), hdr, plaintext);
        secure_zero(key_copy.data(), key_copy.size());
        return packet;
    }

    void handle_received(
        const recv_metadata &meta,
        std::span<std::byte> raw,
        move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)> &handler)
    {
        const bool has_magic = raw.size() >= 2
            && raw[0] == std::byte{0x4D}
            && raw[1] == std::byte{0x43};

        if (m_detection == cleartext_detection::reject_all && !has_magic)
            return;

        if (m_detection == cleartext_detection::magic_byte && !has_magic)
        {
            if (m_accept_cleartext)
                handler(std::error_code{}, meta, raw);
            return;
        }

        if (raw.size() < encrypted_header_size)
        {
            // Too short to carry an encrypted-packet header. In attempt_decrypt
            // mode small legitimate cleartext packets (an mDNS query can be
            // ~28 bytes) are still deliverable, consistent with magic_byte mode.
            if (m_detection == cleartext_detection::attempt_decrypt && m_accept_cleartext && !has_magic)
                handler(std::error_code{}, meta, raw);
            return;
        }

        auto hdr = deserialize_header(raw.data());

        const bool is_encrypted_pkt = (hdr.flags & flag_encrypted) != 0;
        if (m_recv_mode == receive_mode::encrypted_only && !is_encrypted_pkt)
            return;
        if (m_recv_mode == receive_mode::auth_only && is_encrypted_pkt)
            return;

        std::array<std::byte, 32> key_copy;
        bool have_key = false;
        bool used_prev = false;
        {
            std::lock_guard lock(m_key_mutex);
            expire_grace_locked();

            if (hdr.epoch == m_epoch || hdr.epoch == m_epoch + 1)
            {
                // m_epoch + 1 is tried with the current key so that rotation
                // does not require simultaneity: it accepts traffic from peers
                // whose epoch counter runs one ahead with the same key material
                // (e.g. a peer provisioned with initial_epoch one beyond ours
                // while a rotation is in flight). A mismatched key fails AEAD
                // verification and the packet is dropped as usual.
                key_copy = m_key;
                have_key = true;
            }
            else if (m_has_prev_key && hdr.epoch == m_epoch - 1)
            {
                key_copy  = m_prev_key;
                have_key  = true;
                used_prev = true;
            }
        }

        if (!have_key)
            return;

        auto result = aead_decrypt(std::span<const std::byte, 32>(key_copy),
                                   std::span<const std::byte>(raw.data(), raw.size()));
        secure_zero(key_copy.data(), key_copy.size());

        if (!result.has_value())
        {
            if (m_detection == cleartext_detection::attempt_decrypt && m_accept_cleartext && !has_magic)
                handler(std::error_code{}, meta, raw);
            return;
        }

        if (m_replay.check_and_record(hdr.sender_id, hdr.sequence).has_value())
            return;

        if (used_prev)
        {
            std::lock_guard lock(m_key_mutex);
            ++m_grace.packets_seen;
        }

        handler(std::error_code{}, meta, std::span<std::byte>(result->data(), result->size()));
    }
};

}

#endif
