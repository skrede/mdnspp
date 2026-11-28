#ifndef HPP_GUARD_MDNSPP_DETAIL_RECV_FILTER_H
#define HPP_GUARD_MDNSPP_DETAIL_RECV_FILTER_H

#include "mdnspp/policy.h"
#include "mdnspp/mdns_options.h"

#include <chrono>
#include <cstdint>
#include <algorithm>
#include <system_error>

namespace mdnspp::detail {

// Consecutive transient receive failures (a persistent ENOMEM or ENOBUFS): the first re-arms at once, each further one
// delays the re-arm, doubling from 10 ms up to a 500 ms cap.
inline constexpr std::chrono::milliseconds transient_backoff_initial{10};
inline constexpr std::chrono::milliseconds transient_backoff_cap{500};

inline std::chrono::milliseconds transient_backoff_delay(uint32_t consecutive_failures) noexcept
{
    const uint32_t doublings = (std::min)(consecutive_failures - 2, uint32_t{6});
    return (std::min)(transient_backoff_initial * (uint32_t{1} << doublings), transient_backoff_cap);
}

// Everything else (ECONNRESET from a stray ICMP, ENOBUFS) is transient.
inline bool is_fatal_receive_error(std::error_code ec) noexcept
{
    return ec == std::errc::operation_canceled || ec == std::errc::bad_file_descriptor;
}

inline bool ttl_accepted(const recv_metadata &meta, uint32_t minimum, ttl_unknown_policy unknown) noexcept
{
    if(meta.ttl.has_value())
        return static_cast<uint32_t>(*meta.ttl) >= minimum;
    return unknown != ttl_unknown_policy::reject;
}

}

#endif
