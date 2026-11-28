// RFC 6762 section 6.7: a query from a source port other than 5353 is a legacy unicast query, answered by unicast
// to the sender with every TTL capped at legacy_unicast_ttl (default 10 s).

#include "helpers.h"

#include "mdnspp/detail/dns_frame.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <chrono>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <variant>
#include <algorithm>
#include <system_error>

namespace {

mdns_options capped_ttl_opts()
{
    mdns_options opts;
    opts.legacy_unicast_ttl = std::chrono::seconds{10};
    return opts;
}

inproc::inproc_socket_options legacy_client_opts()
{
    inproc::inproc_socket_options opts = no_loopback();
    opts.port_override = uint16_t{12345};
    return opts;
}

observer_options count_service_ptrs(int32_t &count)
{
    observer_options opts;
    opts.on_record = [&count](const endpoint &, const mdns_record_variant &rec)
    {
        if(std::holds_alternative<record_ptr>(rec) && std::get<record_ptr>(rec).name == "_http._tcp.local.")
            ++count;
    };
    return opts;
}

std::vector<mdns_record_variant> parse_records(std::span<const std::byte> data)
{
    std::vector<mdns_record_variant> records;
    detail::walk_dns_frame(data, endpoint{}, [&records](mdns_record_variant rv)
    {
        records.push_back(std::move(rv));
    });
    return records;
}

uint32_t max_ttl(const std::vector<mdns_record_variant> &records)
{
    uint32_t m = 0;
    for(const auto &rec : records)
        m = (std::max)(m, std::visit([](const auto &r) { return r.ttl; }, rec));
    return m;
}

struct legacy_fixture
{
    inproc_harness h;
    int32_t multicast_responses;
    live_server live;
    live_observer watching;
    inproc_socket<test_clock> client;

    legacy_fixture()
        : h{}
        , multicast_responses{0}
        , live{h, make_service("LegacyServer._http._tcp.local.", "_http._tcp.local.", "legacy.local.", 8080),
               legacy_aware_opts(), capped_ttl_opts()}
        , watching{h, count_service_ptrs(multicast_responses)}
        , client{h.executor, legacy_client_opts()}
    {
    }
};

}

TEST_CASE("Legacy unicast query from non-5353 port gets unicast response with capped TTL",
          "[inproc][legacy-unicast]")
{
    legacy_fixture f;
    REQUIRE(f.client.assigned_endpoint().port == 12345);

    std::vector<std::byte> received;
    f.client.async_receive([&received](std::error_code, const recv_metadata &, std::span<std::byte> data)
    {
        received.assign(data.begin(), data.end());
    });
    send_ptr_query(f.client);
    f.h.executor.drain();

    REQUIRE_FALSE(received.empty());
    auto records = parse_records(received);
    REQUIRE_FALSE(records.empty());
    CHECK(max_ttl(records) <= 10u);
    CHECK(f.multicast_responses == 0);
}
