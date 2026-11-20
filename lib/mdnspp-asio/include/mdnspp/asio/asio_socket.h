#ifndef HPP_GUARD_MDNSPP_ASIO_ASIO_SOCKET_H
#define HPP_GUARD_MDNSPP_ASIO_ASIO_SOCKET_H

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/recv_datagram.h"
#ifdef _WIN32
#include "mdnspp/detail/native_socket_setup.h"
#endif

#include "mdnspp/asio/detail/asio_socket_setup.h"

#include <asio.hpp>

#include <span>
#include <memory>
#include <vector>
#include <system_error>

namespace mdnspp {

class asio_socket
{
public:
    /// Executor of the underlying socket (asio convention).
    using executor_type = asio::ip::udp::socket::executor_type;

    using receive_handler = move_only_function<void(std::error_code, const mdnspp::recv_metadata &, std::span<std::byte>)>;

    explicit asio_socket(asio::io_context &io)
        : asio_socket(io, socket_options{})
    {}

    explicit asio_socket(asio::io_context &io, std::error_code &ec)
        : asio_socket(io, socket_options{}, ec)
    {}

    explicit asio_socket(asio::io_context &io, const socket_options &opts)
        : m_socket(io)
        , m_buffer(detail::max_udp_payload)
        , m_token(std::make_shared<char>())
        , m_meta(detail::reserved_metadata())
#ifdef _WIN32
        , m_fn_wsarecvmsg(nullptr)
#endif
    {
        std::error_code ec;
        configure(opts, ec);
        if(ec)
            throw std::system_error(ec, "asio_socket construction");
    }

    explicit asio_socket(asio::io_context &io, const socket_options &opts, std::error_code &ec)
        : m_socket(io)
        , m_buffer(detail::max_udp_payload)
        , m_token(std::make_shared<char>())
        , m_meta(detail::reserved_metadata())
#ifdef _WIN32
        , m_fn_wsarecvmsg(nullptr)
#endif
    {
        configure(opts, ec);
    }

    void async_receive(receive_handler handler)
    {
        if(!m_socket.is_open())
            return;
        m_socket.async_wait(
            asio::ip::udp::socket::wait_read,
            [this, token = std::weak_ptr<char>(m_token), handler = std::move(handler)](std::error_code ec) mutable
            {
                if(token.expired())
                    return;
                on_readable(ec, std::move(handler));
            });
    }

    void send(const mdnspp::endpoint &dest, std::span<const std::byte> data)
    {
        std::error_code ec;
        send(dest, data, ec);
        if(ec)
            throw std::system_error(ec, "mdnspp::asio_socket::send");
    }

    void send(const mdnspp::endpoint &dest, std::span<const std::byte> data, std::error_code &ec)
    {
        const asio::ip::udp::endpoint ep = detail::to_udp_endpoint(dest, ec);
        if(ec)
            return;
        m_socket.send_to(asio::buffer(data.data(), data.size()), ep, 0, ec);
    }

    // Invalidates the token so a completion asio already queued is dropped.
    void close()
    {
        if(m_socket.is_open())
        {
            std::error_code ec;
            m_socket.cancel(ec);
            m_socket.close(ec);
        }
        m_token = std::make_shared<char>();
    }

    asio::ip::udp::socket::native_handle_type native_handle() { return m_socket.native_handle(); }

    // asio::basic_socket::get_executor() is non-const but only reads the stored executor.
    executor_type get_executor() const noexcept
    {
        return const_cast<asio::ip::udp::socket &>(m_socket).get_executor();
    }

private:
    asio::ip::udp::socket m_socket;
    std::vector<std::byte> m_buffer;
    std::shared_ptr<char> m_token;
    mdnspp::recv_metadata m_meta;
#ifdef _WIN32
    LPFN_WSARECVMSG m_fn_wsarecvmsg;
#endif

    void configure(const socket_options &opts, std::error_code &ec)
    {
        detail::configure(m_socket, opts, ec);
#ifdef _WIN32
        if(!ec)
            m_fn_wsarecvmsg = detail::load_wsarecvmsg(m_socket.native_handle());
#endif
    }

    void on_readable(std::error_code ec, receive_handler handler)
    {
        if(ec)
        {
            handler(ec, mdnspp::recv_metadata{}, std::span<std::byte>{});
            return;
        }
        const detail::datagram_result result = read_datagram();
        if(result.would_block || result.truncated)
            async_receive(std::move(handler));
        else if(result.ec)
            handler(result.ec, mdnspp::recv_metadata{}, std::span<std::byte>{});
        else
            handler(std::error_code{}, m_meta, std::span<std::byte>(m_buffer.data(), result.size));
    }

    detail::datagram_result read_datagram()
    {
#ifdef _WIN32
        return detail::recv_datagram(m_socket.native_handle(), m_buffer, m_fn_wsarecvmsg, m_meta);
#else
        return detail::recv_datagram(m_socket.native_handle(), m_buffer, m_meta);
#endif
    }
};

}

static_assert(mdnspp::socket_like<mdnspp::asio_socket>, "asio_socket must satisfy socket_like");

#endif
