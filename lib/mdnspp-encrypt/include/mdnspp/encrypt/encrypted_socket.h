#ifndef HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_SOCKET_H
#define HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_SOCKET_H

#include "mdnspp/policy.h"
#include "mdnspp/encrypt/aead.h"
#include "mdnspp/encrypt/replay_window.h"
#include "mdnspp/encrypt/packet_header.h"
#include "mdnspp/encrypt/encrypt_options.h"
#include "mdnspp/encrypt/encrypt_socket_options.h"

#include <span>
#include <chrono>
#include <atomic>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <optional>
#include <algorithm>
#include <system_error>

namespace mdnspp {

template <SocketLike InnerSocket>
class encrypted_socket
{
public:
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
    {
        init_crypto();
        std::ranges::copy(opts.encrypt.psk.bytes(), m_key.begin());
        opts.encrypt.validate();
    }

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
    {
        init_crypto();
        std::ranges::copy(opts.encrypt.psk.bytes(), m_key.begin());
        opts.encrypt.validate();
    }

    encrypted_socket(const encrypted_socket &) = delete;
    encrypted_socket &operator=(const encrypted_socket &) = delete;
    encrypted_socket(encrypted_socket &&other) noexcept = default;
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

    void update_key(secure_key new_psk, grace_period gp)
    {
        assert((gp.duration.has_value() || gp.packet_count.has_value())
            && "grace_period: at least one of duration or packet_count must be set");

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
    std::array<std::byte, 32> m_key{};
    std::array<std::byte, 32> m_prev_key{};
    uint32_t m_sender_id{0};
    uint32_t m_epoch{0};
    std::atomic<uint64_t> m_seq_counter{0};
    replay_window m_replay;
    bool m_accept_cleartext{false};
    bool m_has_prev_key{false};
    bool m_auth_only{false};
    cleartext_detection m_detection{cleartext_detection::magic_byte};
    receive_mode m_recv_mode{receive_mode::accept_both};
    grace_period_state m_grace{};

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

    std::vector<std::byte> build_encrypted_packet(std::span<const std::byte> plaintext)
    {
        encrypted_packet_header hdr;
        hdr.sender_id = m_sender_id;
        hdr.sequence  = m_seq_counter.fetch_add(1, std::memory_order_relaxed) + 1;
        hdr.epoch     = m_epoch;
        hdr.flags     = m_auth_only ? uint8_t{0} : flag_encrypted;
        return aead_encrypt(std::span<const std::byte, 32>(m_key), hdr, plaintext);
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
            return;

        auto hdr = deserialize_header(raw.data());

        const bool is_encrypted_pkt = (hdr.flags & flag_encrypted) != 0;
        if (m_recv_mode == receive_mode::encrypted_only && !is_encrypted_pkt)
            return;
        if (m_recv_mode == receive_mode::auth_only && is_encrypted_pkt)
            return;

        std::span<const std::byte, 32> current_span(m_key);
        std::span<const std::byte, 32> prev_span(m_prev_key);

        std::span<const std::byte, 32> const *selected_key = nullptr;

        if (hdr.epoch == m_epoch)
        {
            selected_key = &current_span;
        }
        else if (m_has_prev_key && !is_grace_expired() && hdr.epoch == m_epoch - 1)
        {
            selected_key = &prev_span;
        }

        if (!selected_key)
            return;

        auto result = aead_decrypt(*selected_key,
                                   std::span<const std::byte>(raw.data(), raw.size()));
        if (!result.has_value())
        {
            if (m_detection == cleartext_detection::attempt_decrypt && m_accept_cleartext && !has_magic)
                handler(std::error_code{}, meta, raw);
            return;
        }

        if (m_replay.check_and_record(hdr.sender_id, hdr.sequence).has_value())
            return;

        if (selected_key == &prev_span)
            ++m_grace.packets_seen;

        handler(std::error_code{}, meta, std::span<std::byte>(result->data(), result->size()));
    }
};

}

#endif
