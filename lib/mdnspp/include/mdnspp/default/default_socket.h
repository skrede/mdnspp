#ifndef HPP_GUARD_MDNSPP_DEFAULT_DEFAULT_SOCKET_H
#define HPP_GUARD_MDNSPP_DEFAULT_DEFAULT_SOCKET_H

#include "mdnspp/default/default_context.h"

#include "mdnspp/policy.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/native_sockaddr.h"
#include "mdnspp/detail/native_socket_setup.h"

#include <span>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <optional>
#include <system_error>

namespace mdnspp {

class default_socket
{
public:
    explicit default_socket(default_context &ctx)
        : default_socket(ctx, detail::open_and_configure(socket_options{}))
    {
    }

    explicit default_socket(default_context &ctx, std::error_code &ec)
        : default_socket(ctx, detail::open_and_configure(socket_options{}, ec))
    {
    }

    explicit default_socket(default_context &ctx, const socket_options &opts)
        : default_socket(ctx, detail::open_and_configure(opts))
    {
    }

    explicit default_socket(default_context &ctx, const socket_options &opts, std::error_code &ec)
        : default_socket(ctx, detail::open_and_configure(opts, ec))
    {
    }

    ~default_socket()
    {
        close();
    }

    default_socket(const default_socket &) = delete;
    default_socket &operator=(const default_socket &) = delete;
    default_socket(default_socket &&) = delete;
    default_socket &operator=(default_socket &&) = delete;

    void async_receive(detail::receive_handler handler)
    {
        m_ctx.arm_receive(m_fd, std::move(handler));
    }

    detail::native_socket_t native_handle() const noexcept
    {
        return m_fd;
    }

    uint32_t interface_index() const noexcept
    {
        return m_interface_index;
    }

    void send(const endpoint &dest, std::span<const std::byte> data)
    {
        std::error_code ec;
        send(dest, data, ec);
        if(ec)
            throw std::system_error(ec, "mdnspp::default_socket::send");
    }

    void send(const endpoint &dest, std::span<const std::byte> data, std::error_code &ec)
    {
        const std::optional<detail::sockaddr_result> addr = detail::build_sockaddr(dest);
        if(!addr)
        {
            ec = std::make_error_code(std::errc::invalid_argument);
            return;
        }
        const sockaddr *to = reinterpret_cast<const sockaddr *>(&addr->ss);
#ifdef _WIN32
        const int sent = ::sendto(m_fd, reinterpret_cast<const char *>(data.data()),
                                  static_cast<int>(data.size()), 0, to, static_cast<int>(addr->len));
        ec = sent == SOCKET_ERROR ? std::error_code(::WSAGetLastError(), std::system_category()) : std::error_code{};
#else
        const ssize_t sent = ::sendto(m_fd, data.data(), data.size(), 0, to, addr->len);
        ec = sent < 0 ? std::error_code(errno, std::system_category()) : std::error_code{};
#endif
    }

    void close()
    {
        if(m_fd == detail::invalid_socket)
            return;
        m_ctx.deregister_socket(m_fd);
        detail::close_socket(m_fd);
        m_fd = detail::invalid_socket;
    }

private:
    default_context &m_ctx;
    uint32_t m_interface_index;
    detail::native_socket_t m_fd;

    default_socket(default_context &ctx, detail::opened_socket opened)
        : m_ctx{ctx}
        , m_interface_index{opened.interface_index}
        , m_fd{opened.fd}
    {
        register_open_socket();
    }

    void register_open_socket()
    {
        if(m_fd == detail::invalid_socket)
            return;
#ifdef _WIN32
        m_ctx.register_socket(m_fd, detail::load_wsarecvmsg(m_fd));
#else
        m_ctx.register_socket(m_fd);
#endif
    }
};

static_assert(mdnspp::socket_like<mdnspp::default_socket>, "default_socket must satisfy socket_like; check async_receive/send/close signatures");

}

#endif
