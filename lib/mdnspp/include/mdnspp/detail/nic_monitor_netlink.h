#ifndef HPP_GUARD_MDNSPP_DETAIL_NIC_MONITOR_NETLINK_H
#define HPP_GUARD_MDNSPP_DETAIL_NIC_MONITOR_NETLINK_H

#include "mdnspp/basic_nic_monitor.h"

#ifdef __linux__

#include "mdnspp/detail/native_socket.h"

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <memory>
#include <cstddef>
#include <system_error>

namespace mdnspp {

namespace detail {

inline native_socket_t open_netlink_socket()
{
    native_socket_t fd = ::socket(AF_NETLINK,
                                  SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
                                  NETLINK_ROUTE);
    if(fd == invalid_socket)
        return invalid_socket;

    sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = static_cast<unsigned int>(
        RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR);

    if(::bind(fd, reinterpret_cast<const sockaddr *>(&sa), sizeof(sa)) != 0)
    {
        close_socket(fd);
        return invalid_socket;
    }
    return fd;
}

inline bool drain_netlink_socket(native_socket_t fd)
{
    std::array<std::byte, 8192> buf{};
    bool changed = false;
    while(true)
    {
        ssize_t n = ::recv(fd, buf.data(), buf.size(), MSG_DONTWAIT);
        if(n > 0)
        {
            changed = true;
            continue;
        }
        // ENOBUFS: the kernel dropped notifications because the socket buffer overflowed, so events were lost
        // and the interface list must be resynchronized regardless.
        if(n < 0 && errno == ENOBUFS)
        {
            changed = true;
            continue;
        }
        break;
    }
    return changed;
}

}

template <policy_like P>
bool basic_nic_monitor<P>::start_native_backend()
{
    m_nl_fd = detail::open_netlink_socket();
    if(m_nl_fd == detail::invalid_socket)
        return false;

    arm_netlink_poll();
    return true;
}

template <policy_like P>
void basic_nic_monitor<P>::stop_native_backend()
{
    m_nl_timer.cancel();
    if(m_nl_fd != detail::invalid_socket)
    {
        detail::close_socket(m_nl_fd);
        m_nl_fd = detail::invalid_socket;
    }
}

// The netlink socket is drained from a short timer rather than registered with the policy executor, which keeps
// the backend portable across all policy types.
template <policy_like P>
void basic_nic_monitor<P>::arm_netlink_poll()
{
    if(m_stopped.load(std::memory_order_acquire) || m_nl_fd == detail::invalid_socket)
        return;

    m_nl_timer.expires_after(std::chrono::milliseconds(100));
    auto weak = std::weak_ptr<bool>(m_alive);
    m_nl_timer.async_wait([this, weak](std::error_code ec)
    {
        if(ec || weak.expired()) return;
        if(m_nl_fd == detail::invalid_socket) return;

        if(detail::drain_netlink_socket(m_nl_fd))
        {
            std::error_code enum_ec;
            auto interfaces = enumerate_interfaces(enum_ec);
            if(!enum_ec)
                apply_diff(std::move(interfaces));
        }

        arm_netlink_poll();
    });
}

}

#endif

#endif
