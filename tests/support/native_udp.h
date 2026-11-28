#ifndef HPP_GUARD_MDNSPP_SUPPORT_NATIVE_UDP_H
#define HPP_GUARD_MDNSPP_SUPPORT_NATIVE_UDP_H

#include "mdnspp/detail/native_socket.h"

#include <catch2/catch_test_macros.hpp>

#include <fcntl.h>
#include <unistd.h>

#include <netinet/in.h>

#include <sys/socket.h>

#include <cstdint>

namespace mdnspp::test_support {

class udp_socket
{
public:
    udp_socket()
        : m_fd{::socket(AF_INET, SOCK_DGRAM, 0)}
    {
        REQUIRE(m_fd >= 0);
        ::fcntl(m_fd, F_SETFL, ::fcntl(m_fd, F_GETFL) | O_NONBLOCK);
    }

    ~udp_socket()
    {
        if(m_fd >= 0)
            ::close(m_fd);
    }

    udp_socket(const udp_socket &) = delete;
    udp_socket &operator=(const udp_socket &) = delete;

    detail::native_socket_t fd() const
    {
        return m_fd;
    }

    void close_behind_registry()
    {
        ::close(m_fd);
        m_fd = -1;
    }

private:
    detail::native_socket_t m_fd;
};

inline sockaddr_in loopback(uint16_t port)
{
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return addr;
}

inline uint16_t bind_loopback(detail::native_socket_t fd)
{
    sockaddr_in addr = loopback(0);
    socklen_t len = sizeof(addr);
    REQUIRE(::bind(fd, reinterpret_cast<sockaddr *>(&addr), len) == 0);
    REQUIRE(::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len) == 0);
    return ntohs(addr.sin_port);
}

}

#endif
