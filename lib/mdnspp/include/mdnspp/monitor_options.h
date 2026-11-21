#ifndef HPP_GUARD_MDNSPP_MONITOR_OPTIONS_H
#define HPP_GUARD_MDNSPP_MONITOR_OPTIONS_H

#include "mdnspp/callback_types.h"
#include "mdnspp/resolved_service.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_enums.h"

namespace mdnspp {

enum class monitor_mode
{
    observe,
    ttl_refresh,
    discover,
};

enum class update_event
{
    added,
    removed,
};

enum class loss_reason
{
    timeout,
    goodbye,
    unwatched,
};

struct monitor_options
{
    move_only_function<void(const resolved_service &)> on_found{};
    move_only_function<void(const resolved_service &, update_event, dns_type)> on_updated{};
    move_only_function<void(const resolved_service &, loss_reason)> on_lost{};
    error_handler on_error{};
    monitor_mode mode{monitor_mode::discover};
};

}

#endif
