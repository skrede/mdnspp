#ifndef HPP_GUARD_MDNSPP_DETAIL_POLL_SET_H
#define HPP_GUARD_MDNSPP_DETAIL_POLL_SET_H

#include "mdnspp/detail/platform.h"
#include "mdnspp/detail/native_socket.h"
#include "mdnspp/detail/socket_registry.h"

#include <vector>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <system_error>

namespace mdnspp::detail {

struct ready_socket
{
    native_socket_t fd;
    int16_t revents;
};

class poll_set
{
public:
    bool wait(native_socket_t wake_fd, const socket_registry &sockets, int timeout_ms, std::error_code &ec)
    {
        m_fds.clear();
        m_fds.push_back({wake_fd, POLLIN, 0});
        sockets.build_pollfds(m_fds);
        const bool polled = poll_sockets(m_fds.data(), static_cast<nfds_t>(m_fds.size()), timeout_ms) >= 0;
        ec = polled ? std::error_code{} : last_poll_error();
        return polled;
    }

    bool wake_ready() const noexcept
    {
        return !m_fds.empty() && (m_fds[0].revents & POLLIN) != 0;
    }

    void ready_sockets(std::vector<ready_socket> &out) const
    {
        constexpr int32_t serviced = POLLIN | POLLERR | POLLHUP | POLLNVAL;
        out.clear();
        for(std::size_t i = 1; i < m_fds.size(); ++i)
            if((m_fds[i].revents & serviced) != 0)
                out.push_back({m_fds[i].fd, static_cast<int16_t>(m_fds[i].revents)});
    }

private:
    std::vector<pollfd> m_fds;

    static std::error_code last_poll_error() noexcept
    {
#ifdef _WIN32
        return std::error_code(::WSAGetLastError(), std::system_category());
#else
        const int err = errno;
        return err == EINTR ? std::error_code{} : std::error_code(err, std::generic_category());
#endif
    }
};

}

#endif
