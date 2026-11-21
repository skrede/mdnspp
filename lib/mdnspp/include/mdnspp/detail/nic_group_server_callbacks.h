#ifndef HPP_GUARD_MDNSPP_DETAIL_NIC_GROUP_SERVER_CALLBACKS_H
#define HPP_GUARD_MDNSPP_DETAIL_NIC_GROUP_SERVER_CALLBACKS_H

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_enums.h"

#include "mdnspp/endpoint.h"
#include "mdnspp/service_options.h"

#include <memory>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <string_view>
#include <system_error>

namespace mdnspp::detail {

struct shared_server_callbacks
{
    service_options::conflict_callback on_conflict;
    move_only_function<void(const endpoint &, dns_type, response_mode)> on_query;
    move_only_function<void(const endpoint &, std::size_t)> on_tc_continuation;
    move_only_function<void(std::error_code, std::string_view)> on_error;
};

// The stored elements are cloned per NIC and move_only_function members cannot be copied, so the callbacks move
// into one bundle per element that every per-NIC server built from it forwards to.
inline std::shared_ptr<shared_server_callbacks> share_server_callbacks(service_options &svc)
{
    return std::make_shared<shared_server_callbacks>(shared_server_callbacks{
        .on_conflict        = std::move(svc.on_conflict),
        .on_query           = std::move(svc.on_query),
        .on_tc_continuation = std::move(svc.on_tc_continuation),
        .on_error           = std::move(svc.on_error),
    });
}

inline service_options clone_service_options(const service_options &svc)
{
    return service_options{
        .announce_count            = svc.announce_count,
        .announce_interval         = svc.announce_interval,
        .send_goodbye              = svc.send_goodbye,
        .suppress_known_answers    = svc.suppress_known_answers,
        .respond_to_meta_queries   = svc.respond_to_meta_queries,
        .announce_subtypes         = svc.announce_subtypes,
        .probe_count               = svc.probe_count,
        .probe_interval            = svc.probe_interval,
        .probe_initial_delay_max   = svc.probe_initial_delay_max,
        .respond_to_legacy_unicast = svc.respond_to_legacy_unicast,
        .ptr_ttl                   = svc.ptr_ttl,
        .srv_ttl                   = svc.srv_ttl,
        .txt_ttl                   = svc.txt_ttl,
        .a_ttl                     = svc.a_ttl,
        .aaaa_ttl                  = svc.aaaa_ttl,
        .fallback_record_ttl       = svc.fallback_record_ttl,
        .probe_authority_ttl       = svc.probe_authority_ttl,
        .probe_defer_delay         = svc.probe_defer_delay,
    };
}

inline void forward_shared_callbacks(service_options &svc, const std::shared_ptr<shared_server_callbacks> &cbs)
{
    if(cbs->on_conflict)
        svc.on_conflict = [cbs](std::string_view conflicting_name, uint32_t attempt, conflict_type type)
        {
            return cbs->on_conflict(conflicting_name, attempt, type);
        };
    if(cbs->on_query)
        svc.on_query = [cbs](const endpoint &sender, dns_type type, response_mode mode)
        {
            cbs->on_query(sender, type, mode);
        };
    if(cbs->on_tc_continuation)
        svc.on_tc_continuation = [cbs](const endpoint &sender, std::size_t continuation_count)
        {
            cbs->on_tc_continuation(sender, continuation_count);
        };
    if(cbs->on_error)
        svc.on_error = [cbs](std::error_code ec, std::string_view context)
        {
            cbs->on_error(ec, context);
        };
}

}

#endif
