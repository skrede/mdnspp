#ifndef HPP_GUARD_MDNSPP_MONITOR_HELPERS_H
#define HPP_GUARD_MDNSPP_MONITOR_HELPERS_H

#include "mdnspp/service_info.h"
#include "mdnspp/service_options.h"
#include "mdnspp/basic_service_monitor.h"

#include "mdnspp/detail/dns_wire.h"

#include "mdnspp/testing/mock_policy.h"
#include "mdnspp/testing/test_clock.h"

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>

using mdnspp::testing::MockPolicy;
using mdnspp::testing::test_clock;
using mdnspp::testing::mock_executor;

using test_monitor = mdnspp::basic_service_monitor<MockPolicy, test_clock>;

namespace {

mdnspp::service_options make_uniform_opts(uint32_t ttl)
{
    mdnspp::service_options opts;
    auto s = std::chrono::seconds{ttl};
    opts.ptr_ttl    = s;
    opts.srv_ttl    = s;
    opts.txt_ttl    = s;
    opts.a_ttl      = s;
    opts.aaaa_ttl   = s;
    opts.record_ttl = s;
    return opts;
}

std::vector<std::byte> make_ptr_packet(const std::string &service_type,
                                       const std::string &instance_name,
                                       const std::string &hostname,
                                       const std::string &ipv4,
                                       uint32_t ttl = 4500)
{
    mdnspp::service_info info;
    info.service_type = service_type;
    info.service_name = instance_name;
    info.hostname     = hostname;
    info.port         = 8080;
    info.address_ipv4 = ipv4;
    return mdnspp::detail::build_dns_response(info, mdnspp::dns_type::ptr, make_uniform_opts(ttl));
}

std::vector<std::byte> make_srv_packet(const std::string &instance_name,
                                       const std::string &hostname,
                                       uint16_t port = 8080,
                                       uint32_t ttl  = 4500)
{
    mdnspp::service_info info;
    info.service_type = "_http._tcp.local";
    info.service_name = instance_name;
    info.hostname     = hostname;
    info.port         = port;
    info.address_ipv4 = "1.2.3.4";
    return mdnspp::detail::build_dns_response(info, mdnspp::dns_type::srv, make_uniform_opts(ttl));
}

std::vector<std::byte> make_a_packet(const std::string &service_type,
                                     const std::string &instance_name,
                                     const std::string &hostname,
                                     const std::string &ipv4,
                                     uint32_t ttl = 4500)
{
    mdnspp::service_info info;
    info.service_type = service_type;
    info.service_name = instance_name;
    info.hostname     = hostname;
    info.port         = 8080;
    info.address_ipv4 = ipv4;
    return mdnspp::detail::build_dns_response(info, mdnspp::dns_type::a, make_uniform_opts(ttl));
}

std::vector<std::byte> make_txt_packet(const std::string &service_type,
                                       const std::string &instance_name,
                                       const std::string &hostname,
                                       const std::vector<mdnspp::service_txt> &txt,
                                       uint32_t ttl = 4500)
{
    mdnspp::service_info info;
    info.service_type  = service_type;
    info.service_name  = instance_name;
    info.hostname      = hostname;
    info.port          = 8080;
    info.txt_records   = txt;
    return mdnspp::detail::build_dns_response(info, mdnspp::dns_type::txt, make_uniform_opts(ttl));
}

mdnspp::endpoint default_sender()
{
    mdnspp::endpoint ep;
    ep.address = "224.0.0.251";
    ep.port    = 5353;
    return ep;
}

}

#endif
