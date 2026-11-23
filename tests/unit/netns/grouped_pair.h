#ifndef HPP_GUARD_MDNSPP_NETNS_GROUPED_PAIR_H
#define HPP_GUARD_MDNSPP_NETNS_GROUPED_PAIR_H

#include "netns/bound_peers.h"

#include "mdnspp/mdns_options.h"
#include "mdnspp/basic_service_server.h"

#include "mdnspp/detail/sibling_records.h"

#include <chrono>
#include <memory>
#include <string>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

inline mdnspp::service_info grouped_service()
{
    mdnspp::service_info info = attribution_service();
    info.service_name = "Grouped._http._tcp.local.";
    return info;
}

inline mdnspp::service_options recording_conflicts(bool &seen)
{
    return mdnspp::service_options{
        .on_conflict = [&seen](std::string_view, uint32_t, mdnspp::conflict_type) -> std::optional<std::string>
        {
            seen = true;
            return std::nullopt;
        },
        .probe_initial_delay_max = std::chrono::milliseconds{0}};
}

// Two servers that share one sibling registry are members of a group, as the per-NIC servers of a nic_group are, but
// each reports its own conflicts.
class grouped_pair
{
    using server_type = mdnspp::basic_service_server<mdnspp::default_policy>;

public:
    grouped_pair(mdnspp::default_context &ctx, const std::string &group)
        : m_d0_conflict(false)
        , m_d1_conflict(false)
        , m_siblings(std::make_shared<mdnspp::detail::sibling_records>())
        , m_d0(ctx, grouped_service(), recording_conflicts(m_d0_conflict), bound_to("d0", group),
               mdnspp::mdns_options{}, m_siblings, 0)
        , m_d1(ctx, grouped_service(), recording_conflicts(m_d1_conflict), bound_to("d1", group),
               mdnspp::mdns_options{}, m_siblings, 0)
    {
        m_d0.async_start();
        m_d1.async_start();
    }

    bool d0_conflict() const { return m_d0_conflict; }

    bool d1_conflict() const { return m_d1_conflict; }

private:
    bool m_d0_conflict;
    bool m_d1_conflict;
    std::shared_ptr<mdnspp::detail::sibling_records> m_siblings;
    server_type m_d0;
    server_type m_d1;
};

#endif
