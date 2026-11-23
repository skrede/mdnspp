#ifndef HPP_GUARD_MDNSPP_GATE_HELPERS_H
#define HPP_GUARD_MDNSPP_GATE_HELPERS_H

#include "metadata.h"

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/service_info.h"
#include "mdnspp/basic_querier.h"
#include "mdnspp/query_options.h"
#include "mdnspp/basic_observer.h"
#include "mdnspp/monitor_options.h"
#include "mdnspp/service_options.h"
#include "mdnspp/observer_options.h"
#include "mdnspp/resolved_service.h"
#include "mdnspp/basic_service_server.h"
#include "mdnspp/basic_service_monitor.h"
#include "mdnspp/basic_service_discovery.h"

#include "mdnspp/detail/dns_query.h"
#include "mdnspp/detail/dns_response.h"

#include "mdnspp/testing/test_clock.h"
#include "mdnspp/testing/mock_policy.h"

#include <chrono>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <variant>
#include <algorithm>
#include <string_view>
#include <system_error>

using namespace mdnspp;
using namespace mdnspp::testing;
using namespace std::chrono_literals;

inline constexpr uint16_t response_flags = 0x8400;
inline constexpr uint16_t mdns_port = 5353;

inline std::vector<std::byte> with_flags(std::vector<std::byte> packet, uint16_t flags)
{
    packet[2] = static_cast<std::byte>(flags >> 8);
    packet[3] = static_cast<std::byte>(flags & 0xFFU);
    return packet;
}

inline service_info gate_service(std::string_view instance)
{
    service_info info;
    info.service_name = std::string(instance) + "._http._tcp.local.";
    info.service_type = "_http._tcp.local.";
    info.hostname = "gate.local.";
    info.port = 8080;
    info.address_ipv4 = "192.0.2.1";
    return info;
}

inline std::vector<std::byte> service_response(std::string_view instance)
{
    return detail::build_dns_response(gate_service(instance), dns_type::ptr, service_options{});
}

inline std::vector<std::byte> service_query()
{
    return detail::build_dns_query("_http._tcp.local.", dns_type::ptr);
}

inline std::size_t count_instance(const std::vector<mdns_record_variant> &records, std::string_view instance)
{
    return static_cast<std::size_t>(std::ranges::count_if(records, [instance](const mdns_record_variant &rec)
    {
        const auto *ptr = std::get_if<record_ptr>(&rec);
        return ptr != nullptr && ptr->ptr_name.find(instance) != dns_name::npos;
    }));
}

template <typename Rig>
void feed(Rig &rig, std::vector<std::byte> packet, recv_metadata meta)
{
    rig.peer.socket().inject_receive(std::move(meta), std::move(packet));
    rig.ex.drain_posted();
}

template <typename Rig>
void feed(Rig &rig, std::vector<std::byte> packet)
{
    feed(rig, std::move(packet), rig.peer.socket().default_metadata());
}

struct querier_rig
{
    explicit querier_rig(response_mode mode = response_mode::multicast)
        : ex{}
        , peer{ex, query_options{.silence_timeout = 500ms}}
    {
        peer.async_query("_http._tcp.local.", dns_type::ptr, [](std::error_code, std::vector<mdns_record_variant>) {},
                         mode);
    }

    std::size_t reported(std::string_view instance) const { return count_instance(peer.results(), instance); }

    mock_executor ex;
    basic_querier<mock_policy> peer;
};

struct observer_rig
{
    observer_rig()
        : records{}
        , ex{}
        , peer{ex, observer_options{.on_record = [this](const endpoint &, const mdns_record_variant &rec)
          {
              records.push_back(rec);
          }}}
    {
        peer.async_observe();
    }

    std::size_t reported(std::string_view instance) const { return count_instance(records, instance); }

    std::vector<mdns_record_variant> records;
    mock_executor ex;
    basic_observer<mock_policy> peer;
};

struct monitor_rig
{
    monitor_rig()
        : found{}
        , ex{}
        , peer{ex, monitor_options{.on_found = [this](const resolved_service &svc)
          {
              found.push_back(svc.instance_name.str());
          }}}
    {
        test_clock::reset();
        peer.watch("_http._tcp.local.");
        peer.async_start();
        ex.drain_posted();
    }

    std::size_t reported(std::string_view instance) const
    {
        return static_cast<std::size_t>(std::ranges::count_if(found, [instance](const std::string &name)
        {
            return name.starts_with(instance);
        }));
    }

    std::vector<std::string> found;
    mock_executor ex;
    basic_service_monitor<mock_policy, test_clock> peer;
};

struct discovery_rig
{
    discovery_rig()
        : ex{}
        , peer{ex, query_options{.silence_timeout = 500ms}}
    {
        peer.async_discover("_http._tcp.local.", [](std::error_code, std::vector<mdns_record_variant>) {});
    }

    std::size_t reported(std::string_view instance) const { return count_instance(peer.results(), instance); }

    mock_executor ex;
    basic_service_discovery<mock_policy> peer;
};

struct server_rig
{
    explicit server_rig(service_options opts = {})
        : ex{}
        , peer{ex, gate_service("Gate"), std::move(opts)}
    {
        peer.async_start();
        for(uint32_t i = 0; i < 5; ++i)
            peer.timer().fire();
        peer.socket().clear_sent();
    }

    mock_executor ex;
    basic_service_server<mock_policy> peer;
};

#endif
