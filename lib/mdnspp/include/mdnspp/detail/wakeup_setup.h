#ifndef HPP_GUARD_MDNSPP_DETAIL_WAKEUP_SETUP_H
#define HPP_GUARD_MDNSPP_DETAIL_WAKEUP_SETUP_H

#include "mdnspp/detail/native_socket.h"

#include <cerrno>
#include <system_error>

namespace mdnspp::detail {

#if defined(_WIN32)
inline std::error_code wakeup_win32_error()
{
    return std::error_code(::WSAGetLastError(), std::system_category());
}

inline native_socket_t make_wakeup_udp_socket(std::error_code &ec)
{
    const native_socket_t fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(fd == INVALID_SOCKET)
        ec = wakeup_win32_error();
    return fd;
}

inline sockaddr_in bind_wakeup_loopback_recv(native_socket_t recv, std::error_code &ec)
{
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;
    if(::bind(recv, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == SOCKET_ERROR)
    {
        ec = wakeup_win32_error();
        return addr;
    }

    int len = sizeof(addr);
    if(::getsockname(recv, reinterpret_cast<sockaddr *>(&addr), &len) == SOCKET_ERROR)
        ec = wakeup_win32_error();
    return addr;
}

inline void create_wakeup_loopback_pair(native_socket_t &recv, native_socket_t &send, std::error_code &ec)
{
    ec.clear();
    recv = make_wakeup_udp_socket(ec);
    if(ec)
        return;
    sockaddr_in addr = bind_wakeup_loopback_recv(recv, ec);
    if(ec)
        return;
    send = make_wakeup_udp_socket(ec);
    if(ec)
        return;
    if(::connect(send, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == SOCKET_ERROR)
    {
        ec = wakeup_win32_error();
        return;
    }

    u_long mode = 1;
    if(::ioctlsocket(recv, FIONBIO, &mode) == SOCKET_ERROR)
        ec = wakeup_win32_error();
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

inline void create_wakeup_pipe(native_socket_t (&ends)[2], std::error_code &ec)
{
    ec.clear();
    if(::pipe(ends) != 0)
    {
        ec = std::error_code(errno, std::generic_category());
        return;
    }

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
        ec = std::error_code(err, std::generic_category());
        return;
    }
}
#endif

}

#endif
