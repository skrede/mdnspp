#ifndef HPP_GUARD_MDNSPP_DETAIL_WAKEUP_FD_H
#define HPP_GUARD_MDNSPP_DETAIL_WAKEUP_FD_H

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

    void create()
    {
#if defined(__linux__)
        m_fd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if(m_fd < 0)
            throw std::system_error(errno, std::generic_category(), "eventfd");
#elif defined(_WIN32)
        try
        {
            create_loopback_pair();
        }
        catch(...)
        {
            close();
            throw;
        }
#else
        create_pipe();
#endif
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

#if defined(_WIN32)
    static std::system_error win32_error(const char *what)
    {
        return std::system_error(::WSAGetLastError(), std::system_category(), what);
    }

    static native_socket_t make_udp_socket(const char *what)
    {
        const native_socket_t fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(fd == INVALID_SOCKET)
            throw win32_error(what);
        return fd;
    }

    sockaddr_in bind_loopback_recv()
    {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if(::bind(m_recv, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == SOCKET_ERROR)
            throw win32_error("bind(wakeup_recv)");

        int len = sizeof(addr);
        if(::getsockname(m_recv, reinterpret_cast<sockaddr *>(&addr), &len) == SOCKET_ERROR)
            throw win32_error("getsockname");
        return addr;
    }

    void create_loopback_pair()
    {
        m_recv = make_udp_socket("socket(wakeup_recv)");
        sockaddr_in addr = bind_loopback_recv();
        m_send = make_udp_socket("socket(wakeup_send)");
        if(::connect(m_send, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == SOCKET_ERROR)
            throw win32_error("connect(wakeup_send)");

        u_long mode = 1;
        if(::ioctlsocket(m_recv, FIONBIO, &mode) == SOCKET_ERROR)
            throw win32_error("ioctlsocket(wakeup_recv)");
    }
#elif !defined(__linux__)
    void create_pipe()
    {
        if(::pipe(m_pipe) != 0)
            throw std::system_error(errno, std::generic_category(), "pipe");

        for(const int fd : m_pipe)
        {
            const int flags = ::fcntl(fd, F_GETFL, 0);
            if(flags >= 0 && ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0)
                continue;
            const int err = errno;
            close();
            throw std::system_error(err, std::generic_category(), "fcntl(O_NONBLOCK)");
        }
    }
#endif
};

}

#endif
