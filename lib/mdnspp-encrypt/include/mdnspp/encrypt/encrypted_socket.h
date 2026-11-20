#ifndef HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_SOCKET_H
#define HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_SOCKET_H

#include "mdnspp/policy.h"
#include "mdnspp/encrypt/key_ring.h"
#include "mdnspp/encrypt/packet_header.h"
#include "mdnspp/encrypt/encrypted_send.h"
#include "mdnspp/encrypt/encrypt_options.h"
#include "mdnspp/encrypt/encrypted_receive.h"
#include "mdnspp/encrypt/encrypted_receiver.h"
#include "mdnspp/encrypt/encrypt_socket_options.h"

#include <span>
#include <chrono>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <type_traits>
#include <system_error>

namespace mdnspp::encrypt {

// Thread-safety contract: send() is as thread-safe as the inner socket's send(), but concurrent send()
// on one socket is not supported: the send buffer and the sequence counter are shared send-path state.
// update_key() may be called from any thread, concurrently with send and receive; key material is copied
// under an internal mutex, AEAD runs outside it. async_receive() and handler invocation follow the inner
// socket's executor semantics; the replay window and receive buffer are confined to the receive path.
template <socket_like InnerSocket>
class encrypted_socket
{
    struct delegated {};

    using receive_handler = move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)>;

public:
    static constexpr std::chrono::seconds default_grace_duration{key_ring::default_grace_duration};

    // The executor-only constructors satisfy policy_like. Such a socket has no usable key: send and
    // update_key report std::errc::operation_not_permitted and async_receive never completes.
    template <typename Executor>
        requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
    explicit encrypted_socket(Executor &&ex)
        : encrypted_socket(delegated{}, [&] { return InnerSocket(std::forward<Executor>(ex)); },
                           encrypt_options{}, &without_key)
    {
    }

    template <typename Executor>
        requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
    explicit encrypted_socket(Executor &&ex, std::error_code &ec)
        : encrypted_socket(delegated{}, [&] { return InnerSocket(std::forward<Executor>(ex), ec); },
                           encrypt_options{}, &without_key)
    {
    }

    // Throws std::system_error with std::errc::invalid_argument if opts.encrypt.validate() fails, or with
    // std::errc::not_supported if libsodium cannot be initialized; both checks run before the key is copied.
    template <typename Executor>
        requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
    explicit encrypted_socket(Executor &&ex, const encrypt_socket_options &opts)
        : encrypted_socket(delegated{},
                           [&] { return InnerSocket(std::forward<Executor>(ex), static_cast<const socket_options &>(opts)); },
                           opts.encrypt, &validate_or_throw)
    {
    }

    // Sets ec to std::errc::invalid_argument if opts.encrypt.validate() fails, or to std::errc::not_supported
    // if libsodium cannot be initialized; the socket is then left without a usable key.
    template <typename Executor>
        requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
    explicit encrypted_socket(Executor &&ex, const encrypt_socket_options &opts, std::error_code &ec)
        : encrypted_socket(delegated{},
                           [&] { return InnerSocket(std::forward<Executor>(ex), static_cast<const socket_options &>(opts), ec); },
                           opts.encrypt, [&ec](const encrypt_options &o) { return ec ? ec : (ec = usable_options(o)); })
    {
    }

    encrypted_socket(const encrypted_socket &) = delete;
    encrypted_socket &operator=(const encrypted_socket &) = delete;

    void close()
    {
        m_receiver.close();
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
        m_receiver.arm(std::move(handler));
    }

    // The current key stays accepted for the previous epoch until the grace
    // period expires; a gp setting neither bound gets default_grace_duration.
    void update_key(secure_key new_psk, grace_period gp)
    {
        std::error_code ec;
        update_key(std::move(new_psk), gp, ec);
        if(ec)
            throw std::system_error(ec, "mdnspp::encrypt: update_key");
    }

    void update_key(secure_key new_psk, grace_period gp, std::error_code &ec)
    {
        ec = m_keys.update(std::move(new_psk), gp);
    }

    InnerSocket &inner() noexcept { return m_inner; }
    const InnerSocket &inner() const noexcept { return m_inner; }

private:
    InnerSocket m_inner;
    key_ring m_keys;
    encrypted_receiver<InnerSocket> m_receiver;
    uint64_t m_seq_counter;
    encrypted_packet_header m_header;
    std::vector<std::byte> m_send_buf;

    // Only a keyed ring draws a session ID: an unkeyed socket never sends, and a failed libsodium
    // initialization leaves the ring unkeyed, so the uninitialized CSPRNG is never read.
    template <typename MakeInner, typename Check>
    encrypted_socket(delegated, MakeInner &&make_inner, const encrypt_options &opts, Check &&check)
        : m_inner(make_inner())
        // MSVC rejects a conditional expression whose operands are prvalues of a non-movable type.
        , m_keys(key_ring::make(opts, !check(opts)))
        , m_receiver(m_inner, m_keys, opts)
        , m_seq_counter(0)
        , m_header(header_template(opts, m_keys.has_key() ? random_session_id() : 0))
        , m_send_buf(detail::max_udp_payload)
    {
    }
};

}

#endif
