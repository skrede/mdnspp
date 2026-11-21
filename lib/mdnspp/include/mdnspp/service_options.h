#ifndef HPP_GUARD_MDNSPP_SERVICE_OPTIONS_H
#define HPP_GUARD_MDNSPP_SERVICE_OPTIONS_H

#include "mdnspp/endpoint.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_enums.h"

#include <chrono>
#include <string>
#include <cstdint>
#include <optional>
#include <string_view>
#include <system_error>

namespace mdnspp {

struct service_options
{
    using conflict_callback = move_only_function<
        std::optional<std::string>(std::string_view conflicting_name, uint32_t attempt, conflict_type type)>;

    conflict_callback on_conflict{};
    move_only_function<void(const endpoint &sender, dns_type type, response_mode mode)> on_query{};
    move_only_function<void(const endpoint &sender, std::size_t continuation_count)> on_tc_continuation{};
    move_only_function<void(std::error_code ec, std::string_view context)> on_error{};
    uint8_t announce_count{2};
    std::chrono::milliseconds announce_interval{1000};
    bool send_goodbye{true};
    bool suppress_known_answers{true};
    bool respond_to_meta_queries{true};
    bool announce_subtypes{false};
    uint8_t probe_count{3};
    std::chrono::milliseconds probe_interval{250};
    std::chrono::milliseconds probe_initial_delay_max{250};
    bool respond_to_legacy_unicast{true};
    std::chrono::seconds ptr_ttl{4500};
    std::chrono::seconds srv_ttl{120};
    std::chrono::seconds txt_ttl{4500};
    std::chrono::seconds a_ttl{120};
    std::chrono::seconds aaaa_ttl{120};
    std::chrono::seconds fallback_record_ttl{4500};
    std::chrono::seconds probe_authority_ttl{120};
    std::chrono::milliseconds probe_defer_delay{1000};
};

}

#endif
