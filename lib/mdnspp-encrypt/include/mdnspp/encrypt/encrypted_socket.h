#ifndef HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_SOCKET_H
#define HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_SOCKET_H

#include "mdnspp/policy.h"
#include "mdnspp/encrypt/key_ring.h"
#include "mdnspp/encrypt/packet_header.h"
#include "mdnspp/encrypt/replay_window.h"
#include "mdnspp/encrypt/encrypted_send.h"
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

// Thread-safety contract: send() is as thread-safe as the inner socket's send(), but concurrent
// send() on one socket is not supported (shared send buffer). update_key() may be called from
// any thread, concurrently with send and receive; key material is copied under an internal
// mutex, AEAD runs outside it. async_receive() and handler invocation follow the inner socket's
// executor semantics; the replay window and receive buffer are confined to the receive path.
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

    // Plaintext over max_udp_payload - encrypted_overhead is not sent: buffer_too_small (thrown here).
    void send(const endpoint &dest, std::span<const std::byte> plaintext)
    {
        std::error_code ec;
        send(dest, plaintext, ec);
        if(ec)
            throw std::system_error(ec, "mdnspp::encrypt: send");
    }

    void send(const endpoint &dest, std::span<const std::byte> plaintext, std::error_code &ec)
    {
        std::size_t written = 0;
        ec = seal_outgoing(m_keys, m_seq_counter, m_header, plaintext, m_send_buf, written);
        if(!ec)
            m_inner.send(dest, std::span<const std::byte>(m_send_buf.data(), written), ec);
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
    std::vector<std::byte> m_send_buf;
    std::vector<std::byte> m_recv_buf;
    bool m_closed;
    bool m_arming;
    bool m_rearm_requested;

    template <typename MakeInner, typename Check>
    encrypted_socket(delegated, MakeInner &&make_inner, const encrypt_options &opts, Check &&check)
        : m_inner(make_inner())
        // MSVC rejects a conditional expression whose operands are prvalues of a non-movable type.
        , m_keys(key_ring::make(opts, !check(opts)))
        , m_seq_counter(0)
        , m_replay(opts.replay_window_size, opts.max_senders, opts.max_sessions_per_sender)
        , m_rules(rules_of(opts))
        , m_header(header_template(opts, random_session_id()))
        , m_send_buf(detail::max_udp_payload)
        , m_recv_buf(detail::max_udp_payload)
        , m_closed(false)
        , m_arming(false)
        , m_rearm_requested(false)
    {
        init_crypto();
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

        const auto opened = open_packet(m_keys, m_replay, m_rules, raw, m_recv_buf);
        if(opened.outcome == receive_outcome::drop)
            return arm_inner();
        const bool plain = opened.outcome == receive_outcome::deliver_plain;
        complete(std::error_code{}, meta, plain ? std::span<std::byte>(m_recv_buf.data(), opened.written) : raw);
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
