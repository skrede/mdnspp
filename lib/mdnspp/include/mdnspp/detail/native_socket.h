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
    struct checked
    {
    };

public:
    winsock_guard()
        : winsock_guard(checked{}, std::error_code{})
    {
    }

    explicit winsock_guard(std::error_code &ec)
#ifdef _WIN32
        : m_started{start(ec)}
#endif
    {
#ifndef _WIN32
        ec.clear();
#endif
    }

    ~winsock_guard()
    {
#ifdef _WIN32
        if(m_started)
            ::WSACleanup();
#endif
    }

    winsock_guard(const winsock_guard &) = delete;
    winsock_guard &operator=(const winsock_guard &) = delete;
    winsock_guard(winsock_guard &&) = delete;
    winsock_guard &operator=(winsock_guard &&) = delete;

private:
#ifdef _WIN32
    bool m_started;
#endif

    winsock_guard(checked, std::error_code ec)
        : winsock_guard(ec)
    {
        if(ec)
            throw std::system_error(ec, "WSAStartup failed");
    }

#ifdef _WIN32
    static bool start(std::error_code &ec)
    {
        WSADATA data{};
        const int rc = ::WSAStartup(MAKEWORD(2, 2), &data);
        ec = rc == 0 ? std::error_code{} : std::error_code(rc, std::system_category());
        return rc == 0;
    }
#endif
};

}

#endif
