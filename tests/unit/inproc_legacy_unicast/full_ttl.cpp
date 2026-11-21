#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <variant>

namespace {

service_options full_ttl_opts()
{
    service_options opts = legacy_aware_opts();
    opts.ptr_ttl = std::chrono::seconds{4500};
    opts.srv_ttl = std::chrono::seconds{4500};
    opts.a_ttl = std::chrono::seconds{4500};
    opts.txt_ttl = std::chrono::seconds{4500};
    opts.fallback_record_ttl = std::chrono::seconds{4500};
    return opts;
}

mdns_options fast_response_opts()
{
    mdns_options opts;
    opts.response_delay_min = std::chrono::milliseconds{1};
    opts.response_delay_max = std::chrono::milliseconds{1};
    return opts;
}

observer_options track_service_ptrs(int32_t &count, uint32_t &ttl)
{
    observer_options opts;
    opts.on_record = [&count, &ttl](const endpoint &, const mdns_record_variant &rec)
    {
        if(!std::holds_alternative<record_ptr>(rec))
            return;
        const auto &ptr = std::get<record_ptr>(rec);
        if(ptr.name == "_http._tcp.local.")
        {
            ++count;
            ttl = ptr.ttl;
        }
    };
    return opts;
}

struct normal_fixture
{
    inproc_harness h;
    uint32_t ptr_ttl;
    int32_t multicast_ptrs;
    live_server live;
    live_observer watching;
    inproc_socket<test_clock> client;

    normal_fixture()
        : h{}
        , ptr_ttl{0}
        , multicast_ptrs{0}
        , live{h, make_service("NormalServer._http._tcp.local.", "_http._tcp.local.", "normal.local.", 9090),
               full_ttl_opts(), fast_response_opts()}
        , watching{h, track_service_ptrs(multicast_ptrs, ptr_ttl)}
        , client{h.executor}
    {
    }
};

}

TEST_CASE("Normal query from port 5353 gets multicast response with full TTLs",
          "[inproc][legacy-unicast]")
{
    normal_fixture f;
    REQUIRE(f.client.assigned_endpoint().port == 5353);

    send_ptr_query(f.client);
    f.h.executor.drain();
    f.h.advance(std::chrono::milliseconds{5});

    REQUIRE(f.multicast_ptrs >= 1);
    CHECK(f.ptr_ttl == 4500u);
}
