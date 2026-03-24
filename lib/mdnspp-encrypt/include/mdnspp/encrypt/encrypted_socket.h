#ifndef HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_SOCKET_H
#define HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_SOCKET_H

#include "mdnspp/policy.h"
#include "mdnspp/encrypt/aead.h"
#include "mdnspp/encrypt/replay_window.h"
#include "mdnspp/encrypt/packet_header.h"
#include "mdnspp/encrypt/encrypt_socket_options.h"

#include <span>
#include <atomic>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
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
        , m_detection(opts.encrypt.detection)
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
        , m_accept_cleartext(opts.encrypt.accept_cleartext)
        , m_detection(opts.encrypt.detection)
        , m_replay(opts.encrypt.replay_window_size, opts.encrypt.max_senders)
    {
        init_crypto();
        std::ranges::copy(opts.encrypt.psk.bytes(), m_key.begin());
        opts.encrypt.validate();
    }

    encrypted_socket(const encrypted_socket &) = delete;
    encrypted_socket &operator=(const encrypted_socket &) = delete;
    encrypted_socket(encrypted_socket &&other) noexcept = default;
    encrypted_socket &operator=(encrypted_socket &&) = delete;

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
        detail::move_only_function<void(const recv_metadata &, std::span<std::byte>)> handler)
    {
        m_inner.async_receive(
            [this, h = std::move(handler)](const recv_metadata &meta,
                                           std::span<std::byte> raw) mutable
            {
                handle_received(meta, raw, h);
            });
    }

    InnerSocket &inner() noexcept { return m_inner; }
    const InnerSocket &inner() const noexcept { return m_inner; }

private:
    InnerSocket m_inner;
    std::array<std::byte, 32> m_key{};
    uint32_t m_sender_id{0};
    std::atomic<uint64_t> m_seq_counter{0};
    replay_window m_replay;
    bool m_accept_cleartext{false};
    cleartext_detection m_detection{cleartext_detection::magic_byte};

    std::vector<std::byte> build_encrypted_packet(std::span<const std::byte> plaintext)
    {
        encrypted_packet_header hdr;
        hdr.sender_id = m_sender_id;
        hdr.sequence  = m_seq_counter.fetch_add(1, std::memory_order_relaxed) + 1;
        hdr.epoch     = 0;
        hdr.flags     = flag_encrypted;
        return aead_encrypt(std::span<const std::byte, 32>(m_key), hdr, plaintext);
    }

    void handle_received(
        const recv_metadata &meta,
        std::span<std::byte> raw,
        detail::move_only_function<void(const recv_metadata &, std::span<std::byte>)> &handler)
    {
        const bool has_magic = raw.size() >= 2
            && raw[0] == std::byte{0x4D}
            && raw[1] == std::byte{0x43};

        if (m_detection == cleartext_detection::reject_all && !has_magic)
            return;

        if (m_detection == cleartext_detection::magic_byte && !has_magic)
        {
            if (m_accept_cleartext)
                handler(meta, raw);
            return;
        }

        auto result = aead_decrypt(std::span<const std::byte, 32>(m_key),
                                   std::span<const std::byte>(raw.data(), raw.size()));
        if (!result.has_value())
        {
            if (m_detection == cleartext_detection::attempt_decrypt && m_accept_cleartext && !has_magic)
                handler(meta, raw);
            return;
        }

        auto hdr = deserialize_header(raw.data());
        if (m_replay.check_and_record(hdr.sender_id, hdr.sequence).has_value())
            return;

        handler(meta, std::span<std::byte>(result->data(), result->size()));
    }
};

}

#endif
