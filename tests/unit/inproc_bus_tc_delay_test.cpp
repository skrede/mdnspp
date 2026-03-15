// tests/unit/inproc_bus_tc_delay_test.cpp
//
// TC continuation delay integration tests.
// Verifies that basic_service_monitor spaces TC continuation packets using
// the tc_continuation_delay timer when tc_continuation_delay > 0.
//
// TEST-12a: TC continuation delay: first packet immediate, subsequent delayed.
// TEST-12b: TC continuation delay zero: all packets sent in same drain cycle.

#include "mdnspp/inproc/inproc_harness.h"
#include "mdnspp/inproc/inproc_socket.h"

#include "mdnspp/service_info.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/monitor_options.h"
#include "mdnspp/service_options.h"

#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_response.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <functional>

using namespace mdnspp;
using mdnspp::inproc::inproc_harness;
using mdnspp::inproc::inproc_socket;
using mdnspp::testing::test_clock;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

namespace {

mdns_options fast_scheduler_opts(std::chrono::milliseconds tc_delay = {})
{
    mdns_options opts;
    opts.initial_interval      = std::chrono::milliseconds{200};
    opts.max_interval          = std::chrono::milliseconds{200};
    opts.tc_continuation_delay = tc_delay;
    opts.max_query_payload     = 200;
    return opts;
}

endpoint mdns_multicast_ep()
{
    return endpoint{"224.0.0.251", 5353};
}

void inject_ptr_response(inproc_harness &h,
                         std::string_view instance_name,
                         uint32_t ttl = 4500)
{
    service_info info;
    info.service_type = "_http._tcp.local.";
    info.service_name = std::string(instance_name);
    info.hostname     = "host.local.";
    info.port         = 80;
    info.address_ipv4 = "192.168.1.1";

    service_options opts;
    opts.ptr_ttl    = std::chrono::seconds{ttl};
    opts.srv_ttl    = std::chrono::seconds{ttl};
    opts.txt_ttl    = std::chrono::seconds{ttl};
    opts.a_ttl      = std::chrono::seconds{ttl};
    opts.aaaa_ttl   = std::chrono::seconds{ttl};
    opts.record_ttl = std::chrono::seconds{ttl};

    auto pkt = detail::build_dns_response(info, dns_type::ptr, opts);

    inproc_socket<test_clock> injector{h.executor};
    injector.send(mdns_multicast_ep(), std::span<const std::byte>(pkt));
    h.executor.drain();
}

} // namespace

// ---------------------------------------------------------------------------
// TEST-12a: TC continuation delay spaces packets
// ---------------------------------------------------------------------------

TEST_CASE("TC continuation delay spaces packets", "[inproc][tc]")
{
    inproc_harness h;

    auto mon_opts = fast_scheduler_opts(std::chrono::milliseconds{50});
    monitor_options m_opts;
    m_opts.mode = monitor_mode::discover;

    auto monitor = h.make_monitor(std::move(m_opts), {}, std::move(mon_opts));
    monitor.watch("_http._tcp.local.");
    monitor.async_start();
    h.executor.drain();

    inject_ptr_response(h, "Instance1._http._tcp.local.");
    inject_ptr_response(h, "Instance2._http._tcp.local.");
    inject_ptr_response(h, "Instance3._http._tcp.local.");
    inject_ptr_response(h, "Instance4._http._tcp.local.");

    std::vector<std::vector<std::byte>> query_packets;

    inproc_socket<test_clock> sniffer{h.executor};

    std::function<void()> arm_sniffer = [&]()
    {
        sniffer.async_receive([&](const mdnspp::recv_metadata &, std::span<std::byte> data)
        {
            if(data.size() >= 3 &&
               (std::to_integer<uint8_t>(data[2]) & 0x80u) == 0)
            {
                query_packets.push_back(std::vector<std::byte>(data.begin(), data.end()));
            }
            arm_sniffer();
        });
    };
    arm_sniffer();

    h.advance(std::chrono::milliseconds{200});

    REQUIRE(query_packets.size() >= 1u);

    std::size_t count_after_initial = query_packets.size();

    h.advance(std::chrono::milliseconds{49});
    CHECK(query_packets.size() == count_after_initial);

    h.advance(std::chrono::milliseconds{1});
    CHECK(query_packets.size() > count_after_initial);
}

// ---------------------------------------------------------------------------
// TEST-12b: TC continuation delay zero sends all packets in same drain cycle
// ---------------------------------------------------------------------------

TEST_CASE("TC continuation delay zero sends all packets immediately", "[inproc][tc]")
{
    inproc_harness h;

    auto mon_opts = fast_scheduler_opts();
    monitor_options m_opts;
    m_opts.mode = monitor_mode::discover;

    auto monitor = h.make_monitor(std::move(m_opts), {}, std::move(mon_opts));
    monitor.watch("_http._tcp.local.");
    monitor.async_start();
    h.executor.drain();

    inject_ptr_response(h, "InstanceA._http._tcp.local.");
    inject_ptr_response(h, "InstanceB._http._tcp.local.");
    inject_ptr_response(h, "InstanceC._http._tcp.local.");
    inject_ptr_response(h, "InstanceD._http._tcp.local.");

    std::vector<std::vector<std::byte>> query_packets;

    inproc_socket<test_clock> sniffer{h.executor};

    std::function<void()> arm_sniffer = [&]()
    {
        sniffer.async_receive([&](const mdnspp::recv_metadata &, std::span<std::byte> data)
        {
            if(data.size() >= 3 &&
               (std::to_integer<uint8_t>(data[2]) & 0x80u) == 0)
            {
                query_packets.push_back(std::vector<std::byte>(data.begin(), data.end()));
            }
            arm_sniffer();
        });
    };
    arm_sniffer();

    h.advance(std::chrono::milliseconds{200});

    CHECK(query_packets.size() > 1u);
}
