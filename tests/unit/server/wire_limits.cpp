#include "fixture.h"
#include "query_helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <variant>

namespace {

constexpr uint32_t rfc2181_max_ttl = 2147483647u;

endpoint legacy_sender()
{
    return endpoint{"10.0.0.1", 12345};
}

mdns_options immediate_responses()
{
    mdns_options mopts;
    mopts.response_delay_min = std::chrono::milliseconds{0};
    mopts.response_delay_max = std::chrono::milliseconds{0};
    return mopts;
}

std::chrono::seconds above_uint32(int64_t extra)
{
    return std::chrono::seconds{(int64_t{1} << 32) + extra};
}

uint32_t ttl_of(const mdns_record_variant &rv)
{
    return std::visit([](const auto &r) { return r.ttl; }, rv);
}

std::vector<uint32_t> ttls_sent_to(const std::vector<sent_packet> &packets, const endpoint &dest)
{
    std::vector<uint32_t> ttls;
    for(const auto &pkt : packets)
    {
        if(pkt.dest != dest)
            continue;
        for(const auto &rv : parse_response(pkt.data))
            ttls.push_back(ttl_of(rv));
    }
    return ttls;
}

}

TEST_CASE("legacy_unicast_ttl above 32 bits caps at 2^31 - 1, not at its low 32 bits", "[service_server][ttl]")
{
    mdns_options mopts = immediate_responses();
    mopts.legacy_unicast_ttl = above_uint32(3);
    server_fixture f{make_test_info(), {}, mopts};
    f.go_live();
    f.clear_sent();
    f.inject(legacy_sender(), make_ptr_query("_http._tcp.local."));

    auto ttls = ttls_sent_to(f.sent(), legacy_sender());
    REQUIRE_FALSE(ttls.empty());
    for(uint32_t ttl : ttls)
        CHECK(ttl >= 120u);
}

TEST_CASE("probe_authority_ttl above 32 bits goes out as 2^31 - 1", "[service_server][ttl][probing]")
{
    server_fixture f{make_test_info(), service_options{.probe_authority_ttl = above_uint32(7)}};
    f.start();
    f.fire();

    auto ttls = ttls_sent_to(f.sent(), mdns_group());
    REQUIRE(ttls.size() == 3);
    for(uint32_t ttl : ttls)
        CHECK(ttl == rfc2181_max_ttl);
}

TEST_CASE("an SRV and fallback TTL with the top bit set go out as 2^31 - 1", "[service_server][ttl]")
{
    service_options opts{.srv_ttl = std::chrono::seconds{int64_t{rfc2181_max_ttl} + 2},
                         .fallback_record_ttl = std::chrono::seconds{int64_t{rfc2181_max_ttl} + 2}};
    server_fixture f{make_test_info(), std::move(opts), immediate_responses()};
    f.go_live();
    f.inject(endpoint{"192.168.1.50", 5353}, build_dns_query("MyService._http._tcp.local.", dns_type::srv));
    f.server.delay_timer().fire();

    auto ttls = ttls_sent_to(f.sent(), mdns_group());
    REQUIRE_FALSE(ttls.empty());
    for(uint32_t ttl : ttls)
        CHECK(ttl <= rfc2181_max_ttl);
    CHECK(contains_record_where<record_srv>(f.sent().back().data,
                                            [](const record_srv &r) { return r.ttl == rfc2181_max_ttl; }));
}

TEST_CASE("a legacy query whose question section cannot be repeated in full gets no reply",
          "[service_server][legacy_unicast]")
{
    server_fixture f{make_test_info(), {}, immediate_responses()};
    f.go_live();
    f.clear_sent();
    auto query = make_ptr_query("_http._tcp.local.");
    query[5] = std::byte{2};
    query.push_back(std::byte{5});
    query.push_back(std::byte{'a'});
    f.inject(legacy_sender(), query);

    REQUIRE_FALSE(sent_to(f.sent(), legacy_sender()));
}
