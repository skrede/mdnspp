#ifndef HPP_GUARD_MDNSPP_DETAIL_NATIVE_SOCKET_H
#define HPP_GUARD_MDNSPP_DETAIL_NATIVE_SOCKET_H

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <mswsock.h>
#else
#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <netinet/in.h>
#  include <poll.h>
#  include <sys/socket.h>
#  include <unistd.h>
#  ifdef __linux__
#    include <sys/eventfd.h>
#  endif
#  ifdef __APPLE__
#    include <net/if_dl.h>
#  endif
#endif

#include <system_error>

namespace mdnspp {
namespace detail {

#ifdef _WIN32
using native_socket_t = SOCKET;
inline constexpr native_socket_t invalid_socket = INVALID_SOCKET;

inline void close_socket(native_socket_t fd) noexcept
{
    ::closesocket(fd);
}

inline int poll_sockets(pollfd *fds, unsigned long nfds, int timeout_ms)
{
    return ::WSAPoll(fds, nfds, timeout_ms);
}
#else
using native_socket_t = int;
inline constexpr native_socket_t invalid_socket = -1;

inline void close_socket(native_socket_t fd) noexcept
{
    ::close(fd);
}

inline int poll_sockets(pollfd *fds, nfds_t nfds, int timeout_ms)
{
    return ::poll(fds, nfds, timeout_ms);
}
#endif

}

class winsock_guard
{
public:
    winsock_guard()
    {
#ifdef _WIN32
        WSADATA data{};
        if(const int rc = ::WSAStartup(MAKEWORD(2, 2), &data); rc != 0)
            throw std::system_error(rc, std::system_category(), "WSAStartup failed");
#endif
    }

    ~winsock_guard()
    {
#ifdef _WIN32
        ::WSACleanup();
#endif
    }

    winsock_guard(const winsock_guard &) = delete;
    winsock_guard &operator=(const winsock_guard &) = delete;
    winsock_guard(winsock_guard &&) = delete;
    winsock_guard &operator=(winsock_guard &&) = delete;
};

}

#endif
