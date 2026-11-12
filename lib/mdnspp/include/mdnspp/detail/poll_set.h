#ifndef HPP_GUARD_MDNSPP_DETAIL_POLL_SET_H
#define HPP_GUARD_MDNSPP_DETAIL_POLL_SET_H

#include "mdnspp/detail/platform.h"
#include "mdnspp/detail/native_socket.h"
#include "mdnspp/detail/socket_registry.h"

#include <vector>
#include <cerrno>
#include <cstddef>

namespace mdnspp::detail {

class poll_set
{
public:
    int wait(native_socket_t wake_fd, const socket_registry &sockets, int timeout_ms)
    {
        m_fds.clear();
        m_fds.push_back({wake_fd, POLLIN, 0});
        sockets.build_pollfds(m_fds);
        return poll_sockets(m_fds.data(), static_cast<nfds_t>(m_fds.size()), timeout_ms);
    }

    static bool interrupted() noexcept
    {
#ifdef _WIN32
        return false;
#else
        return errno == EINTR;
#endif
    }

    bool wake_ready() const noexcept
    {
        return !m_fds.empty() && (m_fds[0].revents & POLLIN) != 0;
    }

    void ready_sockets(std::vector<native_socket_t> &out) const
    {
        out.clear();
        for(std::size_t i = 1; i < m_fds.size(); ++i)
            if(m_fds[i].revents & POLLIN)
                out.push_back(m_fds[i].fd);
    }

private:
    std::vector<pollfd> m_fds;
};

}

#endif
