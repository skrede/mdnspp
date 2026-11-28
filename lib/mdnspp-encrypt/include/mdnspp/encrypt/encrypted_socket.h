#ifndef HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_SOCKET_H
#define HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_SOCKET_H

#include "mdnspp/encrypt/key_ring.h"
#include "mdnspp/encrypt/packet_header.h"
#include "mdnspp/encrypt/encrypted_send.h"
#include "mdnspp/encrypt/encrypt_options.h"
#include "mdnspp/encrypt/encrypted_receive.h"
#include "mdnspp/encrypt/encrypted_receiver.h"
#include "mdnspp/encrypt/encrypt_socket_options.h"

#include "mdnspp/policy.h"

#include "mdnspp/detail/transport_traits.h"

#include <span>
#include <chrono>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <type_traits>
#include <system_error>

namespace mdnspp::encrypt {

template <socket_like InnerSocket>
class encrypted_socket
{
    struct delegated {};

    using receive_handler = move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)>;

public:
    static constexpr std::chrono::seconds default_grace_duration{key_ring::default_grace_duration};
    static constexpr bool in_process_transport{detail::is_in_process_v<InnerSocket>};

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

    template <typename Executor>
        requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
    explicit encrypted_socket(Executor &&ex, const encrypt_socket_options &opts)
        : encrypted_socket(delegated{},
                           [&] { return InnerSocket(std::forward<Executor>(ex), static_cast<const socket_options &>(opts)); },
                           opts.encrypt, &validate_or_throw)
    {
    }

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

    uint32_t interface_index() const noexcept
        requires detail::reports_interface_index<InnerSocket>
    {
        return m_inner.interface_index();
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
