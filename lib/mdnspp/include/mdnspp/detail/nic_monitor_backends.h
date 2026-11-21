#ifndef HPP_GUARD_MDNSPP_DETAIL_NIC_MONITOR_BACKENDS_H
#define HPP_GUARD_MDNSPP_DETAIL_NIC_MONITOR_BACKENDS_H

#include "mdnspp/basic_nic_monitor.h"

#ifdef __APPLE__
#if __has_include(<Network/Network.h>)
#define MDNSPP_HAS_NW_PATH_MONITOR 1
#endif
#endif

#ifdef __linux__
#include "mdnspp/detail/nic_monitor_netlink.h"
#elif defined(__APPLE__) && defined(MDNSPP_HAS_NW_PATH_MONITOR)
#include "mdnspp/detail/nic_monitor_apple.h"
#elif defined(_WIN32)
#include "mdnspp/detail/nic_monitor_windows.h"
#else

namespace mdnspp {

template <policy_like P>
bool basic_nic_monitor<P>::start_native_backend()
{
    return false;
}

template <policy_like P>
void basic_nic_monitor<P>::stop_native_backend()
{
}

}

#endif

#endif
