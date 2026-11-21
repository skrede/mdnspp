#ifndef HPP_GUARD_MDNSPP_DETAIL_NIC_MONITOR_WINDOWS_H
#define HPP_GUARD_MDNSPP_DETAIL_NIC_MONITOR_WINDOWS_H

#include "mdnspp/basic_nic_monitor.h"

#ifdef _WIN32

// ws2tcpip.h must precede iphlpapi.h: netioapi.h declares its user-mode API
// only when ws2ipdef.h has already been included (#ifdef _WS2IPDEF_).
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <memory>
#include <system_error>

namespace mdnspp {

template <policy_like P>
struct basic_nic_monitor<P>::thunk
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

template <policy_like P>
bool basic_nic_monitor<P>::start_native_backend()
{
    m_weak_for_callback = std::weak_ptr<bool>(m_alive);

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

}

#endif

#endif
