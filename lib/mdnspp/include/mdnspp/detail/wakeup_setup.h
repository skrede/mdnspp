#ifndef HPP_GUARD_MDNSPP_DETAIL_WAKEUP_SETUP_H
#define HPP_GUARD_MDNSPP_DETAIL_WAKEUP_SETUP_H

#include "mdnspp/detail/native_socket.h"

#include <cerrno>
#include <system_error>

namespace mdnspp::detail {

#if defined(_WIN32)
inline std::system_error wakeup_win32_error(const char *what)
{
    return std::system_error(::WSAGetLastError(), std::system_category(), what);
}

inline native_socket_t make_wakeup_udp_socket(const char *what)
{
    const native_socket_t fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(fd == INVALID_SOCKET)
        throw wakeup_win32_error(what);
    return fd;
}

inline sockaddr_in bind_wakeup_loopback_recv(native_socket_t recv)
{
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if(::bind(recv, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == SOCKET_ERROR)
        throw wakeup_win32_error("bind(wakeup_recv)");

    int len = sizeof(addr);
    if(::getsockname(recv, reinterpret_cast<sockaddr *>(&addr), &len) == SOCKET_ERROR)
        throw wakeup_win32_error("getsockname");
    return addr;
}

inline void create_wakeup_loopback_pair(native_socket_t &recv, native_socket_t &send)
{
    recv = make_wakeup_udp_socket("socket(wakeup_recv)");
    sockaddr_in addr = bind_wakeup_loopback_recv(recv);
    send = make_wakeup_udp_socket("socket(wakeup_send)");
    if(::connect(send, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == SOCKET_ERROR)
        throw wakeup_win32_error("connect(wakeup_send)");

    u_long mode = 1;
    if(::ioctlsocket(recv, FIONBIO, &mode) == SOCKET_ERROR)
        throw wakeup_win32_error("ioctlsocket(wakeup_recv)");
}
#elif !defined(__linux__)
inline bool configure_wakeup_pipe_end(native_socket_t fd) noexcept
{
    const int status = ::fcntl(fd, F_GETFL, 0);
    if(status < 0 || ::fcntl(fd, F_SETFL, status | O_NONBLOCK) < 0)
        return false;
    const int descriptor = ::fcntl(fd, F_GETFD, 0);
    return descriptor >= 0 && ::fcntl(fd, F_SETFD, descriptor | FD_CLOEXEC) >= 0;
}

inline void create_wakeup_pipe(native_socket_t (&ends)[2])
{
    if(::pipe(ends) != 0)
        throw std::system_error(errno, std::generic_category(), "pipe");

    for(const native_socket_t end : ends)
    {
        if(configure_wakeup_pipe_end(end))
            continue;
        const int err = errno;
        for(native_socket_t &fd : ends)
        {
            close_socket(fd);
            fd = invalid_socket;
        }
        throw std::system_error(err, std::generic_category(), "fcntl");
    }
}
#endif

}

#endif
