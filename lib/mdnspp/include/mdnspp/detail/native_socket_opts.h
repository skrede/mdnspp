#ifndef HPP_GUARD_MDNSPP_DETAIL_NATIVE_SOCKET_OPTS_H
#define HPP_GUARD_MDNSPP_DETAIL_NATIVE_SOCKET_OPTS_H

#include "mdnspp/detail/native_socket.h"

#include <cerrno>
#include <cstdint>
#include <system_error>

namespace mdnspp::detail {

inline std::error_code last_socket_error()
{
#ifdef _WIN32
    return std::error_code(::WSAGetLastError(), std::system_category());
#else
    return std::error_code(errno, std::generic_category());
#endif
}

inline bool set_sock_opt(native_socket_t fd, int32_t level, int32_t optname, const void *optval,
                         socklen_t optlen, std::error_code &ec)
{
#ifdef _WIN32
    const bool failed = ::setsockopt(fd, level, optname, reinterpret_cast<const char *>(optval), optlen) == SOCKET_ERROR;
#else
    const bool failed = ::setsockopt(fd, level, optname, optval, optlen) < 0;
#endif
    if(failed)
        ec = last_socket_error();
    return !failed;
}

template <typename T>
bool set_option(native_socket_t fd, int32_t level, int32_t optname, const T &value, std::error_code &ec)
{
    return set_sock_opt(fd, level, optname, &value, static_cast<socklen_t>(sizeof(T)), ec);
}

inline void set_flag_best_effort(native_socket_t fd, int32_t level, int32_t optname)
{
    std::error_code ignored;
    set_option(fd, level, optname, int32_t{1}, ignored);
}

inline bool set_nonblocking(native_socket_t fd, std::error_code &ec)
{
#ifdef _WIN32
    u_long mode = 1;
    const bool failed = ::ioctlsocket(fd, FIONBIO, &mode) == SOCKET_ERROR;
#else
    const int32_t flags = ::fcntl(fd, F_GETFL, 0);
    const bool failed = flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0;
#endif
    if(failed)
        ec = last_socket_error();
    return !failed;
}

inline bool bind_socket(native_socket_t fd, const sockaddr *addr, socklen_t addrlen, std::error_code &ec)
{
#ifdef _WIN32
    const bool failed = ::bind(fd, addr, static_cast<int>(addrlen)) == SOCKET_ERROR;
#else
    const bool failed = ::bind(fd, addr, addrlen) < 0;
#endif
    if(failed)
        ec = last_socket_error();
    return !failed;
}

}

#endif
