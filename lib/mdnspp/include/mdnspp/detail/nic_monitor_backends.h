#ifndef HPP_GUARD_MDNSPP_DETAIL_NIC_MONITOR_BACKENDS_H
#define HPP_GUARD_MDNSPP_DETAIL_NIC_MONITOR_BACKENDS_H

// This header is included at the bottom of basic_nic_monitor.h and provides
// out-of-line definitions for basic_nic_monitor<P>::start_native_backend() and
// stop_native_backend() under platform-specific #ifdef guards.
//
// Linux:   AF_NETLINK socket, drained via a 100 ms timer — interface change
//          detection therefore has a latency floor of 100 ms.
// macOS:   nw_path_monitor — requires Network.framework (macOS 10.14+).
// Windows: NotifyIpInterfaceChange — requires iphlpapi.
// Other:   Stub returning false → polling fallback.

#include "mdnspp/basic_nic_monitor.h"

#ifdef __linux__
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#ifdef __APPLE__
#if __has_include(<Network/Network.h>)
#define MDNSPP_HAS_NW_PATH_MONITOR 1
#include <Network/Network.h>
#endif
#endif

#ifdef _WIN32
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#endif

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <system_error>

namespace mdnspp {

// ---------------------------------------------------------------------------
// Linux — AF_NETLINK backend
// ---------------------------------------------------------------------------

#ifdef __linux__

template <policy_like P>
bool basic_nic_monitor<P>::start_native_backend()
{
    m_nl_fd = ::socket(AF_NETLINK,
                       SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
                       NETLINK_ROUTE);
    if(m_nl_fd == detail::invalid_socket)
        return false;

    sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = static_cast<unsigned int>(
        RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR);

    if(::bind(m_nl_fd, reinterpret_cast<const sockaddr *>(&sa), sizeof(sa)) != 0)
    {
        detail::close_socket(m_nl_fd);
        m_nl_fd = detail::invalid_socket;
        return false;
    }

    // Poll netlink fd with a short-interval timer.  When data is present the
    // socket is drained and apply_diff(enumerate_interfaces()) is called.
    // Using a timer (rather than directly registering the fd with the policy
    // executor) keeps the implementation portable across all policy types.
    auto schedule_nl_poll = [this]() mutable
    {
        struct helper
        {
            static void arm(basic_nic_monitor<P> *self)
            {
                if(self->m_stopped.load(std::memory_order_acquire) ||
                   self->m_nl_fd == detail::invalid_socket)
                    return;

                self->m_nl_timer.expires_after(std::chrono::milliseconds(100));
                auto weak = std::weak_ptr<bool>(self->m_alive);
                self->m_nl_timer.async_wait([self, weak](std::error_code ec)
                {
                    if(ec || weak.expired()) return;
                    if(self->m_nl_fd == detail::invalid_socket) return;

                    // Drain all pending netlink messages (non-blocking).
                    std::array<std::byte, 8192> buf{};
                    bool changed = false;
                    while(true)
                    {
                        ssize_t n = ::recv(self->m_nl_fd, buf.data(), buf.size(),
                                           MSG_DONTWAIT);
                        if(n > 0)
                        {
                            changed = true;
                            continue;
                        }
                        // ENOBUFS: the kernel dropped notifications because the
                        // socket buffer overflowed — events were lost, so the
                        // interface list must be resynchronized regardless.
                        if(n < 0 && errno == ENOBUFS)
                        {
                            changed = true;
                            continue;
                        }
                        break;
                    }

                    if(changed)
                    {
                        std::error_code enum_ec;
                        auto interfaces = enumerate_interfaces(enum_ec);
                        if(!enum_ec)
                            self->apply_diff(std::move(interfaces));
                    }

                    arm(self);
                });
            }
        };
        helper::arm(this);
    };

    schedule_nl_poll();
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

// ---------------------------------------------------------------------------
// macOS — nw_path_monitor backend
// ---------------------------------------------------------------------------

#elif defined(__APPLE__) && defined(MDNSPP_HAS_NW_PATH_MONITOR)

template <policy_like P>
bool basic_nic_monitor<P>::start_native_backend()
{
    auto *monitor = nw_path_monitor_create();
    if(!monitor)
        return false;

    m_path_monitor = static_cast<void *>(monitor);

    nw_path_monitor_set_queue(monitor,
                              dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));

    auto weak = std::weak_ptr<bool>(m_alive);
    auto *self = this;
    nw_path_monitor_set_update_handler(monitor, ^(nw_path_t /*path*/)
    {
        if(weak.expired()) return;
        P::post(self->m_executor, [self, weak]
        {
            if(weak.expired()) return;
            std::error_code ec;
            auto interfaces = enumerate_interfaces(ec);
            if(!ec)
                self->apply_diff(std::move(interfaces));
        });
    });

    nw_path_monitor_start(monitor);
    return true;
}

template <policy_like P>
void basic_nic_monitor<P>::stop_native_backend()
{
    if(m_path_monitor)
    {
        auto *monitor = static_cast<nw_path_monitor_t>(m_path_monitor);
        nw_path_monitor_cancel(monitor);
        nw_release(monitor);
        m_path_monitor = nullptr;
    }
}

// ---------------------------------------------------------------------------
// Windows — NotifyIpInterfaceChange backend
// ---------------------------------------------------------------------------

#elif defined(_WIN32)

template <policy_like P>
bool basic_nic_monitor<P>::start_native_backend()
{
    m_weak_for_callback = std::weak_ptr<bool>(m_alive);

    struct thunk
    {
        static void WINAPI on_change(void *ctx,
                                     PMIB_IPINTERFACE_ROW /*row*/,
                                     MIB_NOTIFICATION_TYPE /*type*/)
        {
            auto *self = static_cast<basic_nic_monitor<P> *>(ctx);
            auto weak = self->m_weak_for_callback;
            if(weak.expired()) return;
            P::post(self->m_executor, [self, weak]
            {
                if(weak.expired()) return;
                std::error_code ec;
                auto interfaces = enumerate_interfaces(ec);
                if(!ec)
                    self->apply_diff(std::move(interfaces));
            });
        }
    };

    HANDLE handle = nullptr;
    DWORD rc = NotifyIpInterfaceChange(AF_UNSPEC,
                                       &thunk::on_change,
                                       this,
                                       FALSE,
                                       &handle);
    if(rc != NO_ERROR)
        return false;

    m_change_handle = static_cast<void *>(handle);
    return true;
}

template <policy_like P>
void basic_nic_monitor<P>::stop_native_backend()
{
    if(m_change_handle)
    {
        CancelMibChangeNotify2(static_cast<HANDLE>(m_change_handle));
        m_change_handle = nullptr;
    }
}

// ---------------------------------------------------------------------------
// Other / fallback — no native backend
// ---------------------------------------------------------------------------

#else

template <policy_like P>
bool basic_nic_monitor<P>::start_native_backend()
{
    return false; // triggers polling fallback in start()
}

template <policy_like P>
void basic_nic_monitor<P>::stop_native_backend()
{
}

#endif

}

#endif
