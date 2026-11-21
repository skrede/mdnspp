#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_VALIDATE_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_VALIDATE_H

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
           || opts.fallback_record_ttl <= std::chrono::seconds::zero();
}

inline bool invalid_mdns_timing(const mdns_options &mdns_opts)
{
    return mdns_opts.record_ttl <= std::chrono::seconds::zero()
           || mdns_opts.legacy_unicast_ttl <= std::chrono::seconds::zero()
           || mdns_opts.response_delay_min > mdns_opts.response_delay_max
           || mdns_opts.response_delay_min < std::chrono::milliseconds::zero()
           || mdns_opts.tc_wait_min > mdns_opts.tc_wait_max
           || mdns_opts.tc_wait_min < std::chrono::milliseconds::zero();
}

inline bool invalid_mdns_factors(const mdns_options &mdns_opts)
{
    if(mdns_opts.backoff_multiplier < 1.0)
        return true;
    if(mdns_opts.ka_suppression_fraction <= 0.0 || mdns_opts.ka_suppression_fraction >= 1.0
       || mdns_opts.tc_suppression_fraction <= 0.0 || mdns_opts.tc_suppression_fraction >= 1.0)
        return true;
    for(double threshold : mdns_opts.ttl_refresh_thresholds)
    {
        if(threshold <= 0.0 || threshold >= 1.0)
            return true;
    }
    return false;
}

inline std::error_code validate_server_options(const service_info &info,
                                               const service_options &opts,
                                               const mdns_options &mdns_opts)
{
    if(invalid_service_names(info)
       || invalid_schedule(opts)
       || invalid_record_ttls(opts)
       || invalid_mdns_timing(mdns_opts)
       || invalid_mdns_factors(mdns_opts))
        return std::make_error_code(std::errc::invalid_argument);
    return {};
}

}

#endif
