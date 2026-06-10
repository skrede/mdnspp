#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_VALIDATE_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_VALIDATE_H

#include "mdnspp/mdns_options.h"
#include "mdnspp/service_info.h"
#include "mdnspp/service_options.h"

#include "mdnspp/detail/dns_read.h"

#include <chrono>
#include <system_error>

namespace mdnspp::detail {

// Validates the service_options / mdns_options fields the service server
// consumes, plus the encodability of the service names. Returns
// std::errc::invalid_argument on the first violated constraint, or a
// default-constructed error_code when everything is consistent.
inline std::error_code validate_server_options(const service_info &info,
                                               const service_options &opts,
                                               const mdns_options &mdns_opts)
{
    auto invalid = std::make_error_code(std::errc::invalid_argument);

    if(encode_dns_name(info.service_name).empty()
       || encode_dns_name(info.service_type).empty()
       || encode_dns_name(info.hostname).empty())
        return invalid;

    if(opts.probe_count < 1 || opts.announce_count < 1)
        return invalid;

    if(opts.probe_interval <= std::chrono::milliseconds::zero()
       || opts.announce_interval <= std::chrono::milliseconds::zero())
        return invalid;

    if(opts.probe_initial_delay_max < std::chrono::milliseconds::zero()
       || opts.probe_defer_delay < std::chrono::milliseconds::zero())
        return invalid;

    if(opts.ptr_ttl <= std::chrono::seconds::zero()
       || opts.srv_ttl <= std::chrono::seconds::zero()
       || opts.txt_ttl <= std::chrono::seconds::zero()
       || opts.a_ttl <= std::chrono::seconds::zero()
       || opts.aaaa_ttl <= std::chrono::seconds::zero()
       || opts.record_ttl <= std::chrono::seconds::zero())
        return invalid;

    if(mdns_opts.record_ttl <= std::chrono::seconds::zero()
       || mdns_opts.legacy_unicast_ttl <= std::chrono::seconds::zero())
        return invalid;

    if(mdns_opts.response_delay_min > mdns_opts.response_delay_max
       || mdns_opts.response_delay_min < std::chrono::milliseconds::zero())
        return invalid;

    if(mdns_opts.tc_wait_min > mdns_opts.tc_wait_max
       || mdns_opts.tc_wait_min < std::chrono::milliseconds::zero())
        return invalid;

    if(mdns_opts.backoff_multiplier < 1.0)
        return invalid;

    if(mdns_opts.ka_suppression_fraction <= 0.0 || mdns_opts.ka_suppression_fraction >= 1.0
       || mdns_opts.tc_suppression_fraction <= 0.0 || mdns_opts.tc_suppression_fraction >= 1.0)
        return invalid;

    for(double threshold : mdns_opts.ttl_refresh_thresholds)
    {
        if(threshold <= 0.0 || threshold >= 1.0)
            return invalid;
    }

    return {};
}

}

#endif
