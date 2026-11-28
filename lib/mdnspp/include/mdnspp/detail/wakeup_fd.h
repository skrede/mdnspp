#ifndef HPP_GUARD_MDNSPP_DETAIL_WAKEUP_FD_H
#define HPP_GUARD_MDNSPP_DETAIL_WAKEUP_FD_H

#include "mdnspp/detail/wakeup_setup.h"
#include "mdnspp/detail/native_socket.h"

#include <cerrno>
#include <cstdint>
#include <system_error>

namespace mdnspp::detail {

class wakeup_fd
{
public:
    wakeup_fd()
#if defined(__linux__)
        : m_fd{-1}
#elif defined(_WIN32)
        : m_recv{invalid_socket}
        , m_send{invalid_socket}
#else
        : m_pipe{-1, -1}
#endif
    {
    }

    ~wakeup_fd()
    {
        close();
    }

    wakeup_fd(const wakeup_fd &) = delete;
    wakeup_fd &operator=(const wakeup_fd &) = delete;
    wakeup_fd(wakeup_fd &&) = delete;
    wakeup_fd &operator=(wakeup_fd &&) = delete;

    void create(std::error_code &ec)
    {
        close();
#if defined(__linux__)
        m_fd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        ec = m_fd < 0 ? std::error_code(errno, std::generic_category()) : std::error_code{};
#elif defined(_WIN32)
        create_wakeup_loopback_pair(m_recv, m_send, ec);
        if(ec)
            close();
#else
        create_wakeup_pipe(m_pipe, ec);
#endif
    }

    void create()
    {
        std::error_code ec;
        create(ec);
        if(ec)
            throw std::system_error(ec, "mdnspp::detail::wakeup_fd::create");
    }

    void notify() noexcept
    {
#if defined(__linux__)
        const uint64_t one = 1;
        while(::write(m_fd, &one, sizeof(one)) < 0 && errno == EINTR)
        {
        }
#elif defined(_WIN32)
        const char byte = 1;
        (void)::send(m_send, &byte, 1, 0);
#else
        const char byte = 1;
        while(::write(m_pipe[1], &byte, 1) < 0 && errno == EINTR)
        {
        }
#endif
    }

    void drain() noexcept
    {
#if defined(__linux__)
        uint64_t val{};
        (void)::read(m_fd, &val, sizeof(val));
#elif defined(_WIN32)
        char buf[64];
        while(::recv(m_recv, buf, sizeof(buf), 0) > 0)
        {
        }
#else
        char buf[64];
        while(::read(m_pipe[0], buf, sizeof(buf)) > 0)
        {
        }
#endif
    }

    void close() noexcept
    {
#if defined(__linux__)
        close_if_open(m_fd);
#elif defined(_WIN32)
        close_if_open(m_recv);
        close_if_open(m_send);
#else
        close_if_open(m_pipe[0]);
        close_if_open(m_pipe[1]);
#endif
    }

    native_socket_t native() const noexcept
    {
#if defined(__linux__)
        return m_fd;
#elif defined(_WIN32)
        return m_recv;
#else
        return m_pipe[0];
#endif
    }

private:
#if defined(__linux__)
    native_socket_t m_fd;
#elif defined(_WIN32)
    native_socket_t m_recv;
    native_socket_t m_send;
#else
    native_socket_t m_pipe[2];
#endif

    static void close_if_open(native_socket_t &fd) noexcept
    {
        if(fd == invalid_socket)
            return;
        close_socket(fd);
        fd = invalid_socket;
    }
};

}

#endif
