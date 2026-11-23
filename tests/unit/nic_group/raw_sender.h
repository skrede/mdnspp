#ifndef HPP_GUARD_MDNSPP_NIC_GROUP_RAW_SENDER_H
#define HPP_GUARD_MDNSPP_NIC_GROUP_RAW_SENDER_H

#include "fixture.h"
#include "sniffer.h"

#include "mdnspp/inproc/inproc_socket.h"

#include "mdnspp/endpoint.h"
#include "mdnspp/service_info.h"
#include "mdnspp/service_options.h"

#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_response.h"

#include <chrono>
#include <string>
#include <vector>
#include <cstddef>
#include <utility>
#include <optional>

struct raw_service
{
    std::optional<std::string> ipv4{};
    std::optional<std::string> ipv6{};
    std::chrono::seconds srv_ttl{120};
};

inline std::vector<std::byte> response_for(const raw_service &svc, dns_type qtype)
{
    service_info info = make_service("svc._test._tcp.local.");
    info.address_ipv4 = svc.ipv4;
    info.address_ipv6 = svc.ipv6;
    service_options opts;
    opts.srv_ttl = svc.srv_ttl;
    return detail::build_dns_response(info, qtype, opts);
}

struct group_sender
{
    group_sender(inproc_executor<test_clock> &ex, std::string group)
        : destination{group, 5353}
        , socket(ex, sniffer_options(std::move(group)))
    {
    }

    void send(const raw_service &svc, dns_type qtype = dns_type::ptr)
    {
        socket.send(destination, response_for(svc, qtype));
    }

    endpoint destination;
    mdnspp::inproc::inproc_socket<test_clock> socket;
};

struct family_senders
{
    explicit family_senders(inproc_executor<test_clock> &ex)
        : ipv4{ex, ipv4_group}
        , ipv6{ex, ipv6_group}
    {
    }

    group_sender ipv4;
    group_sender ipv6;
};

inline void use_dual_stack_nics(group_fixture &f)
{
    f.nics->clear();
    f.nics->push_back(make_nic(1, "nic1", {"10.0.0.1", "fd00::1"}));
    f.nics->push_back(make_nic(2, "nic2", {"10.0.1.1", "fd00:1::1"}));
}

#endif
