#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_VALIDATE_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_VALIDATE_H

#include "mdnspp/detail/mdns_options_validation.h"

#include "mdnspp/mdns_options.h"
#include "mdnspp/service_info.h"
#include "mdnspp/service_options.h"

#include <chrono>
#include <system_error>

namespace mdnspp::detail {

// dns_name normalizes invalid presentation input to the empty name, so emptiness covers absent and invalid
// names alike; the root name is not a service name either.
inline bool invalid_service_names(const service_info &info)
{
    return info.service_name.empty()
           || info.service_type.empty()
           || info.hostname.empty();
}

inline bool invalid_schedule(const service_options &opts)
{
    return opts.probe_count < 1 || opts.announce_count < 1
           || opts.probe_interval <= std::chrono::milliseconds::zero()
           || opts.announce_interval <= std::chrono::milliseconds::zero()
           || opts.probe_initial_delay_max < std::chrono::milliseconds::zero()
           || opts.probe_defer_delay < std::chrono::milliseconds::zero();
}

inline bool invalid_record_ttls(const service_options &opts)
{
    return opts.ptr_ttl <= std::chrono::seconds::zero()
           || opts.srv_ttl <= std::chrono::seconds::zero()
           || opts.txt_ttl <= std::chrono::seconds::zero()
           || opts.a_ttl <= std::chrono::seconds::zero()
           || opts.aaaa_ttl <= std::chrono::seconds::zero()
           || opts.fallback_record_ttl <= std::chrono::seconds::zero()
           || opts.probe_authority_ttl <= std::chrono::seconds::zero();
}

inline std::error_code validate_server_options(const service_info &info,
                                               const service_options &opts,
                                               const mdns_options &mdns_opts)
{
    if(invalid_service_names(info)
       || invalid_schedule(opts)
       || invalid_record_ttls(opts)
       || mdns_opts.legacy_unicast_ttl <= std::chrono::seconds::zero())
        return std::make_error_code(std::errc::invalid_argument);
    return validate_mdns_options(mdns_opts);
}

}

#endif
