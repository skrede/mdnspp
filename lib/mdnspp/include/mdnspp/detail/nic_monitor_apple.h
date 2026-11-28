#ifndef HPP_GUARD_MDNSPP_DETAIL_NIC_MONITOR_APPLE_H
#define HPP_GUARD_MDNSPP_DETAIL_NIC_MONITOR_APPLE_H

#include "mdnspp/basic_nic_monitor.h"

#if defined(__APPLE__) && defined(MDNSPP_HAS_NW_PATH_MONITOR)

#include <Network/Network.h>

#include <memory>
#include <system_error>

namespace mdnspp {

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

}

#endif

#endif
