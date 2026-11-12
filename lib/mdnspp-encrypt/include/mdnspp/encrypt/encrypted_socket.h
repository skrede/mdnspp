#ifndef HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_SOCKET_H
#define HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_SOCKET_H

#include "mdnspp/policy.h"
#include "mdnspp/encrypt/aead.h"
#include "mdnspp/encrypt/key_ring.h"
#include "mdnspp/encrypt/packet_header.h"
#include "mdnspp/encrypt/replay_window.h"
#include "mdnspp/encrypt/encrypt_options.h"
#include "mdnspp/encrypt/encrypted_receive.h"
#include "mdnspp/encrypt/encrypt_socket_options.h"

#include <span>
#include <atomic>
#include <chrono>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <type_traits>
#include <system_error>

namespace mdnspp::encrypt {

// Thread-safety contract: update_key() and send() may be called from any
// thread, concurrently with each other and with the receive path; key state is
// guarded by an internal mutex (key material is copied under the lock, AEAD
// operations run outside it). async_receive() and handler invocation follow
// the inner socket's executor semantics; the replay window is confined to the
// receive path.
template <socket_like InnerSocket>
class encrypted_socket
{
    struct delegated {};

    using receive_handler = move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)>;

public:
    static constexpr std::chrono::seconds default_grace_duration{key_ring::default_grace_duration};

    // The executor-only constructors satisfy policy_like; a socket built
    // without options holds no key and must be discarded.
    template <typename Executor>
        requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
    explicit encrypted_socket(Executor &&ex)
        : encrypted_socket(delegated{}, [&] { return InnerSocket(std::forward<Executor>(ex)); },
                           encrypt_options{}, &skip_validation)
    {
    }

    template <typename Executor>
        requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
    explicit encrypted_socket(Executor &&ex, std::error_code &ec)
        : encrypted_socket(delegated{}, [&] { return InnerSocket(std::forward<Executor>(ex), ec); },
                           encrypt_options{}, &skip_validation)
    {
    }

    // Throws std::system_error with std::errc::invalid_argument if
    // opts.encrypt.validate() fails; validation runs before the key is copied.
    template <typename Executor>
        requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
    explicit encrypted_socket(Executor &&ex, const encrypt_socket_options &opts)
        : encrypted_socket(delegated{},
                           [&] { return InnerSocket(std::forward<Executor>(ex), static_cast<const socket_options &>(opts)); },
                           opts.encrypt, &validate_or_throw)
    {
    }

    // Sets ec to std::errc::invalid_argument if opts.encrypt.validate() fails;
    // the key is not copied in that case and the socket must not be used.
    template <typename Executor>
        requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
    explicit encrypted_socket(Executor &&ex, const encrypt_socket_options &opts, std::error_code &ec)
        : encrypted_socket(delegated{},
                           [&] { return InnerSocket(std::forward<Executor>(ex), static_cast<const socket_options &>(opts), ec); },
                           opts.encrypt, [&ec](const encrypt_options &o) { return ec ? ec : (ec = o.validate()); })
    {
    }

    encrypted_socket(const encrypted_socket &) = delete;
    encrypted_socket &operator=(const encrypted_socket &) = delete;

    void close()
    {
        m_closed = true;
        m_receive_cb = nullptr;
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

    void async_receive(receive_handler handler)
    {
        if(m_closed)
            return;
        m_receive_cb = std::move(handler);
        arm_inner();
    }

    // The current key stays accepted for the previous epoch until the grace
    // period expires; a gp setting neither bound gets default_grace_duration.
    void update_key(secure_key new_psk, grace_period gp)
    {
        m_keys.update(std::move(new_psk), gp);
    }

    InnerSocket &inner() noexcept { return m_inner; }
    const InnerSocket &inner() const noexcept { return m_inner; }

private:
    InnerSocket m_inner;
    key_ring m_keys;
    receive_handler m_receive_cb;
    std::atomic<uint64_t> m_seq_counter;
    replay_window m_replay;
    receive_rules m_rules;
    encrypted_packet_header m_header;
    bool m_closed;
    bool m_arming;
    bool m_rearm_requested;

    template <typename MakeInner, typename Check>
    encrypted_socket(delegated, MakeInner &&make_inner, const encrypt_options &opts, Check &&check)
        : m_inner(make_inner())
        , m_keys(check(opts) ? key_ring() : key_ring(opts.psk.bytes(), opts.initial_epoch))
        , m_seq_counter(random_sequence_start())
        , m_replay(opts.replay_window_size, opts.max_senders)
        , m_rules(rules_of(opts))
        , m_header(header_template(opts))
        , m_closed(false)
        , m_arming(false)
        , m_rearm_requested(false)
    {
        init_crypto();
    }

    std::vector<std::byte> build_encrypted_packet(std::span<const std::byte> plaintext)
    {
        auto hdr = m_header;
        hdr.sequence = m_seq_counter.fetch_add(1, std::memory_order_relaxed) + 1;
        const auto sending = m_keys.key_for_send();
        hdr.epoch = sending.epoch;
        return aead_encrypt(sending.key.span(), hdr, plaintext);
    }

    // Iterative so an inner socket that completes inline cannot grow the
    // stack however many consecutive packets are rejected.
    void arm_inner()
    {
        m_rearm_requested = true;
        if(m_arming)
            return;
        m_arming = true;
        while(m_rearm_requested && !m_closed)
        {
            m_rearm_requested = false;
            m_inner.async_receive([this](std::error_code ec, const recv_metadata &meta, std::span<std::byte> raw)
            {
                on_inner(ec, meta, raw);
            });
        }
        m_arming = false;
    }

    void on_inner(std::error_code ec, const recv_metadata &meta, std::span<std::byte> raw)
    {
        if(m_closed)
            return;
        if(ec)
            return complete(ec, meta, raw);

        auto opened = open_packet(m_keys, m_replay, m_rules, raw);
        if(opened.outcome == receive_outcome::drop)
            return arm_inner();
        const bool plain = opened.outcome == receive_outcome::deliver_plain;
        complete(std::error_code{}, meta, plain ? std::span<std::byte>(opened.plaintext) : raw);
    }

    void complete(std::error_code ec, const recv_metadata &meta, std::span<std::byte> data)
    {
        auto handler = std::exchange(m_receive_cb, nullptr);
        if(handler)
            handler(ec, meta, data);
    }
};

}

#endif
