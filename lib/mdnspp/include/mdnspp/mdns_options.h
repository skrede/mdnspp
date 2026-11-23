#ifndef HPP_GUARD_MDNSPP_MDNS_OPTIONS_H
#define HPP_GUARD_MDNSPP_MDNS_OPTIONS_H

#include <chrono>
#include <vector>
#include <cstddef>
#include <cstdint>

namespace mdnspp {

enum class ttl_unknown_policy { accept, reject };

struct mdns_options
{
    std::chrono::milliseconds initial_interval{std::chrono::seconds(1)};
    std::chrono::milliseconds max_interval{std::chrono::hours(1)};
    double backoff_multiplier{2.0};
    std::vector<double> ttl_refresh_thresholds{0.80, 0.85, 0.90, 0.95};
    double refresh_jitter_pct{0.02};
    std::chrono::milliseconds tc_wait_min{400};
    std::chrono::milliseconds tc_wait_max{500};
    std::chrono::milliseconds response_delay_min{20};
    std::chrono::milliseconds response_delay_max{120};
    std::chrono::seconds legacy_unicast_ttl{10};
    double ka_suppression_fraction{0.5};
    double tc_suppression_fraction{0.5};
    std::size_t max_query_payload{1472};
    std::chrono::microseconds tc_continuation_delay{0};
    uint32_t receive_ttl_minimum{255};
    ttl_unknown_policy unknown_ttl_policy{ttl_unknown_policy::accept};
    std::chrono::milliseconds qu_response_window{std::chrono::seconds(2)};
};

}

#endif
