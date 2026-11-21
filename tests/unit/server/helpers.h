#ifndef HPP_GUARD_MDNSPP_HELPERS_H
#define HPP_GUARD_MDNSPP_HELPERS_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_error.h"
#include "mdnspp/service_info.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/service_options.h"
#include "mdnspp/basic_service_server.h"

#include "mdnspp/detail/dns_wire.h"

#include "mdnspp/testing/mock_policy.h"

#include "support/wire_bytes.h"

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <variant>
#include <optional>

using namespace mdnspp;
using namespace mdnspp::detail;
using namespace mdnspp::testing;
using mdnspp::dns_type;
using mdnspp::test_support::read_u16_be;

inline service_info make_test_service()
{
    service_info info;
    info.service_name = "MyService._http._tcp.local.";
    info.service_type = "_http._tcp.local.";
    info.hostname = "myhost.local.";
    info.port = 8080;
    info.priority = 0;
    info.weight = 0;
    info.address_ipv4 = "192.168.1.10";
    info.address_ipv6 = std::nullopt;
    info.txt_records = {service_txt{"path", "/api"}, service_txt{"ver", std::nullopt}};
    return info;
}

inline std::vector<mdns_record_variant> parse_response(const std::vector<std::byte> &pkt)
{
    std::vector<mdns_record_variant> records;
    walk_dns_frame(std::span<const std::byte>(pkt), endpoint{}, [&](mdns_record_variant rv)
    {
        records.push_back(std::move(rv));
    });
    return records;
}

inline service_info make_test_info()
{
    service_info info;
    info.service_name = "MyService._http._tcp.local.";
    info.service_type = "_http._tcp.local.";
    info.hostname = "myhost.local.";
    info.port = 8080;
    info.priority = 0;
    info.weight = 0;
    info.address_ipv4 = "192.168.1.10";
    info.txt_records = {service_txt{"path", "/api"}};
    return info;
}

inline std::vector<std::byte> make_ptr_query(std::string_view service_type)
{
    return build_dns_query(service_type, dns_type::ptr);
}

// Probing takes four timer fires: the initial delay, probes two and three, then the conflict window. The first
// announcement needs no fire; each further one does.
inline void advance_to_live(basic_service_server<mock_policy> &server, uint32_t announce_count = 2)
{
    for(uint32_t i = 0; i < 4; ++i)
        server.timer().fire();

    for(uint32_t i = 1; i < announce_count; ++i)
        server.timer().fire();
}

inline std::vector<std::byte> make_conflict_response(const service_info &info)
{
    return build_dns_response(info, dns_type::srv, service_options{});
}

#endif
