#include "inproc_bus/helpers.h"

#include "mdnspp/inproc/inproc_socket.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/service_info.h"
#include "mdnspp/monitor_options.h"
#include "mdnspp/service_options.h"

#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_response.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <chrono>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <system_error>

using mdnspp::inproc::inproc_socket;

namespace {

mdns_options tc_scheduler_opts(std::chrono::milliseconds tc_delay)
{
    mdns_options opts = fast_scheduler_opts();
    opts.tc_continuation_delay = tc_delay;
    opts.max_query_payload = 200;
    return opts;
}

monitor_options discover_only()
{
    monitor_options opts;
    opts.mode = monitor_mode::discover;
    return opts;
}

service_options uniform_ttl_opts(uint32_t ttl)
{
    service_options opts;
    opts.ptr_ttl = std::chrono::seconds{ttl};
    opts.srv_ttl = std::chrono::seconds{ttl};
    opts.txt_ttl = std::chrono::seconds{ttl};
    opts.a_ttl = std::chrono::seconds{ttl};
    opts.aaaa_ttl = std::chrono::seconds{ttl};
    opts.fallback_record_ttl = std::chrono::seconds{ttl};
    return opts;
}

void inject_ptr_response(inproc_harness &h, std::string_view instance_name, uint32_t ttl = 4500)
{
    service_info info = make_service(instance_name, "_http._tcp.local.", "host.local.", 80);
    auto pkt = detail::build_dns_response(info, dns_type::ptr, uniform_ttl_opts(ttl));
    inproc_socket<test_clock> injector{h.executor};
    injector.send(endpoint{"224.0.0.251", 5353}, std::span<const std::byte>(pkt));
    h.executor.drain();
}

struct query_sniffer
{
    explicit query_sniffer(inproc_harness &h)
        : packets{}
        , times{}
        , socket{h.executor}
    {
        arm();
    }

    void arm()
    {
        socket.async_receive([this](std::error_code, const recv_metadata &, std::span<std::byte> data)
        {
            // RFC 1035 section 4.1.1: a clear QR bit marks a query.
            if(data.size() >= 3 && (std::to_integer<uint8_t>(data[2]) & 0x80u) == 0)
            {
                packets.push_back(std::vector<std::byte>(data.begin(), data.end()));
                times.push_back(test_clock::now());
            }
            arm();
        });
    }

    // Declared first so the packets outlive the socket and its pending receive handler.
    std::vector<std::vector<std::byte>> packets;
    std::vector<test_clock::time_point> times;
    inproc_socket<test_clock> socket;
};

}

TEST_CASE("TC continuation delay spaces packets", "[inproc][tc]")
{
    inproc_harness h;
    live_monitor monitor{h, "_http._tcp.local.", discover_only(), tc_scheduler_opts(50ms)};
    inject_ptr_response(h, "Instance1._http._tcp.local.");
    inject_ptr_response(h, "Instance2._http._tcp.local.");
    inject_ptr_response(h, "Instance3._http._tcp.local.");
    inject_ptr_response(h, "Instance4._http._tcp.local.");
    query_sniffer sniffer{h};

    h.advance(200ms);
    REQUIRE(sniffer.packets.size() == 1u);
    std::size_t count_after_initial = sniffer.packets.size();

    h.advance(49ms);
    CHECK(sniffer.packets.size() == count_after_initial);

    h.advance(1ms);
    CHECK(sniffer.packets.size() > count_after_initial);
}

TEST_CASE("TC continuation delay zero sends all packets immediately", "[inproc][tc]")
{
    inproc_harness h;
    live_monitor monitor{h, "_http._tcp.local.", discover_only(), tc_scheduler_opts(0ms)};
    inject_ptr_response(h, "InstanceA._http._tcp.local.");
    inject_ptr_response(h, "InstanceB._http._tcp.local.");
    inject_ptr_response(h, "InstanceC._http._tcp.local.");
    inject_ptr_response(h, "InstanceD._http._tcp.local.");
    query_sniffer sniffer{h};

    // Header and question take 34 bytes and each known-answer PTR 56, so 200 bytes hold two of the four answers.
    h.advance(200ms);
    REQUIRE(sniffer.packets.size() == 2u);
    CHECK(sniffer.times[1] == sniffer.times[0]);
}
