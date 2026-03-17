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

#include <vector>
#include <string>
#include <cstddef>
#include <variant>
#include <optional>

using namespace mdnspp;
using namespace mdnspp::detail;
using namespace mdnspp::testing;
using mdnspp::dns_type;

namespace {

inline uint16_t read_u16_be(const auto &buf, std::size_t offset)
{
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(static_cast<uint8_t>(buf[offset])) << 8) |
        static_cast<uint16_t>(static_cast<uint8_t>(buf[offset + 1])));
}

}

static service_info make_test_service()
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

static std::vector<mdns_record_variant> parse_response(const std::vector<std::byte> &pkt)
{
    std::vector<mdns_record_variant> records;
    walk_dns_frame(std::span<const std::byte>(pkt), endpoint{}, [&](mdns_record_variant rv)
    {
        records.push_back(std::move(rv));
    });
    return records;
}

static service_info make_test_info()
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

static std::vector<std::byte> make_ptr_query(std::string_view service_type)
{
    return build_dns_query(service_type, dns_type::ptr);
}

// Advances a server from probing through announcing to live state.
// Probing: 1 fire (initial delay) + 2 fires (probes 2 and 3) + 1 fire (conflict window) = 4
// Announcing: first announcement is immediate (no fire), then (announce_count - 1) fires
// With default announce_count=2: 4 + 1 = 5 timer fires total.
static void advance_to_live(basic_service_server<MockPolicy> &server, unsigned announce_count = 2)
{
    // 4 timer fires to complete probing
    for(unsigned i = 0; i < 4; ++i)
        server.timer().fire();

    // (announce_count - 1) timer fires for remaining announcements
    for(unsigned i = 1; i < announce_count; ++i)
        server.timer().fire();
}

// Builds a mock DNS response packet that contains a record matching the given service_info.
// This is used to simulate conflict detection during probing.
static std::vector<std::byte> make_conflict_response(const service_info &info)
{
    return build_dns_response(info, dns_type::srv, service_options{});
}

#endif
