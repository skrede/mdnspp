#include "mdnspp/ip_address.h"
#include "mdnspp/monitor_options.h"
#include "mdnspp/resolved_service.h"

#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/nic_family_union.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>
#include <cstdint>
#include <string_view>
#include <initializer_list>

using namespace mdnspp;
using detail::nic_family_union;

namespace {

constexpr address_family v4 = address_family::ipv4;
constexpr address_family v6 = address_family::ipv6;

struct union_events
{
    union_events()
        : fan_in{[this](const resolved_service &svc) { log.push_back("found " + describe(svc)); },
                 [this](const resolved_service &svc, update_event event, dns_type type)
                 {
                     const char *what = event == update_event::added ? "added " : "removed ";
                     log.push_back(what + std::to_string(uint16_t(type)) + " " + describe(svc));
                 },
                 [this](const resolved_service &svc, loss_reason reason)
                 {
                     log.push_back("lost " + std::to_string(int32_t(reason)) + " " + describe(svc));
                 }}
    {
    }

    static std::string describe(const resolved_service &svc)
    {
        std::string text = svc.instance_name.str();
        for(const auto &address : svc.ipv4_addresses)
            text += " " + address;
        for(const auto &address : svc.ipv6_addresses)
            text += " " + address;
        return text;
    }

    std::vector<std::string> log;
    nic_family_union fan_in;
};

resolved_service service(std::string_view name, std::initializer_list<std::string> v4_addresses,
                         std::initializer_list<std::string> v6_addresses = {})
{
    resolved_service svc;
    svc.instance_name = dns_name(name);
    svc.hostname = dns_name("host.local.");
    svc.port = 8080;
    svc.ipv4_addresses = v4_addresses;
    svc.ipv6_addresses = v6_addresses;
    return svc;
}

const std::string aaaa = std::to_string(uint16_t(dns_type::aaaa));
const std::string a = std::to_string(uint16_t(dns_type::a));

}

TEST_CASE("nic_family_union fires found for the first family and updated only when the union grows", "[nic_group]")
{
    union_events e;
    e.fan_in.found(v4, service("svc.local.", {"192.0.2.10"}));
    e.fan_in.found(v6, service("svc.local.", {"192.0.2.10"}));
    e.fan_in.updated(v6, service("svc.local.", {"192.0.2.10"}, {"2001:db8::10"}), update_event::added, dns_type::aaaa);
    e.fan_in.updated(v4, service("svc.local.", {"192.0.2.10"}, {"2001:db8::10"}), update_event::added, dns_type::aaaa);

    CHECK(e.log == std::vector<std::string>{"found svc.local. 192.0.2.10",
                                            "added " + aaaa + " svc.local. 192.0.2.10 2001:db8::10"});
}

TEST_CASE("nic_family_union reports a second family's new address as an update", "[nic_group]")
{
    union_events e;
    e.fan_in.found(v4, service("svc.local.", {"192.0.2.10"}));
    e.fan_in.found(v6, service("svc.local.", {}, {"2001:db8::10"}));

    CHECK(e.log == std::vector<std::string>{"found svc.local. 192.0.2.10",
                                            "added " + aaaa + " svc.local. 192.0.2.10 2001:db8::10"});
}

TEST_CASE("nic_family_union fires lost once the last family lost the service", "[nic_group]")
{
    union_events e;
    e.fan_in.found(v4, service("svc.local.", {"192.0.2.10"}));
    e.fan_in.found(v6, service("svc.local.", {"192.0.2.10"}));
    e.fan_in.lost(v4, service("svc.local.", {"192.0.2.10"}), loss_reason::goodbye);
    e.fan_in.lost(v4, service("svc.local.", {"192.0.2.10"}), loss_reason::goodbye);
    CHECK(e.log.size() == 1);

    e.fan_in.lost(v6, service("svc.local.", {"192.0.2.10"}), loss_reason::timeout);
    e.fan_in.lost(v6, service("svc.local.", {"192.0.2.10"}), loss_reason::timeout);
    e.fan_in.found(v6, service("svc.local.", {"192.0.2.10"}));

    CHECK(e.log == std::vector<std::string>{"found svc.local. 192.0.2.10",
                                            "lost " + std::to_string(int32_t(loss_reason::timeout))
                                                + " svc.local. 192.0.2.10",
                                            "found svc.local. 192.0.2.10"});
}

TEST_CASE("nic_family_union reports the addresses a lost family took with it", "[nic_group]")
{
    union_events e;
    e.fan_in.found(v4, service("svc.local.", {"192.0.2.10"}));
    e.fan_in.found(v6, service("svc.local.", {}, {"2001:db8::10"}));
    e.fan_in.lost(v4, service("svc.local.", {"192.0.2.10"}), loss_reason::goodbye);

    CHECK(e.log.back() == "removed " + a + " svc.local. 2001:db8::10");
}

TEST_CASE("nic_family_union keys instances case-insensitively and keeps instances apart", "[nic_group]")
{
    union_events e;
    e.fan_in.found(v4, service("Svc.local.", {"192.0.2.10"}));
    e.fan_in.found(v6, service("svc.local.", {"192.0.2.10"}));
    e.fan_in.found(v6, service("other.local.", {"192.0.2.20"}));

    CHECK(e.log == std::vector<std::string>{"found Svc.local. 192.0.2.10", "found other.local. 192.0.2.20"});
}
