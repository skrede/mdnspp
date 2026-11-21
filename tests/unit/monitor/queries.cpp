#include "fixture.h"

#include "mdnspp/testing/mock_socket.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>

namespace {

struct tc_counts
{
    uint32_t set;
    uint32_t clear;
};

mdnspp::mdns_options tc_split_options()
{
    mdnspp::mdns_options opts = no_refresh_options();
    opts.max_query_payload = 200; // forces known-answer splitting
    opts.tc_continuation_delay = std::chrono::milliseconds{20};
    return opts;
}

// Enough PTR records per type that the known-answer list of each PTR query exceeds max_query_payload.
void populate_known_answers(test_monitor::socket_type &sock)
{
    for(int32_t i = 0; i < 10; ++i)
    {
        auto inst = "Service" + std::to_string(i);
        sock.inject_receive(default_sender(),
            make_ptr_packet("_a._tcp.local", inst + "._a._tcp.local", "hosta.local", "10.0.0.1"));
        sock.inject_receive(default_sender(),
            make_ptr_packet("_b._tcp.local", inst + "._b._tcp.local", "hostb.local", "10.0.0.2"));
    }
}

tc_counts count_tc_queries(const std::vector<mdnspp::testing::sent_packet> &packets)
{
    tc_counts counts{0, 0};
    for(const auto &pkt : packets)
    {
        REQUIRE(pkt.data.size() >= 12);
        uint16_t flags = static_cast<uint16_t>(
            (static_cast<uint16_t>(std::to_integer<uint8_t>(pkt.data[2])) << 8) |
            static_cast<uint16_t>(std::to_integer<uint8_t>(pkt.data[3])));
        if(flags & 0x8000)
            continue; // not a query
        if(flags & 0x0200)
            ++counts.set;
        else
            ++counts.clear;
    }
    return counts;
}

}

TEST_CASE("query_service_type: sends PTR query immediately in any mode",
          "[monitor]")
{
    monitor_fixture f{mode_options(mdnspp::monitor_mode::observe), no_refresh_options()};
    f.start();
    CHECK(f.socket().sent_packets().empty());

    f.mon.query_service_type("_http._tcp.local");
    f.ex.drain_posted();

    REQUIRE_FALSE(f.socket().sent_packets().empty());
}

TEST_CASE("query_service_instance: sends one multi-question SRV/TXT/A/AAAA query",
          "[monitor]")
{
    monitor_fixture f{mode_options(mdnspp::monitor_mode::observe), no_refresh_options()};
    f.start();
    CHECK(f.socket().sent_packets().empty());

    f.mon.query_service_instance("MyInstance._http._tcp.local");
    f.ex.drain_posted();

    // RFC 6762 section 5: one aggregated packet with four questions
    REQUIRE(f.socket().sent_packets().size() == 1);
    const auto &data = f.socket().sent_packets()[0].data;
    REQUIRE(data.size() >= 12);
    CHECK((static_cast<uint8_t>(data[2]) & 0x80) == 0); // QR = 0
    CHECK(static_cast<uint8_t>(data[4]) == 0x00); // QDCOUNT == 4 (SRV, TXT, A, AAAA)
    CHECK(static_cast<uint8_t>(data[5]) == 0x04);
    CHECK(static_cast<uint8_t>(data[6]) == 0x00); // ANCOUNT == 0
    CHECK(static_cast<uint8_t>(data[7]) == 0x00);
}

TEST_CASE("scheduler: concurrent TC continuation chains for two watches do not cancel each other",
          "[monitor][scheduler][tc]")
{
    monitor_fixture f{mode_options(mdnspp::monitor_mode::observe), tc_split_options()};
    f.watch_and_start({"_a._tcp.local", "_b._tcp.local"});
    populate_known_answers(f.socket());
    f.socket().clear_sent();

    f.mon.query_service_type("_a._tcp.local");
    f.mon.query_service_type("_b._tcp.local");
    f.ex.drain_posted();
    REQUIRE(f.mon.tc_chain_count_for_test() == 2);
    REQUIRE(f.socket().sent_packets().size() == 2); // the first packet of each chain

    for(int32_t guard = 0; guard < 32 && f.mon.tc_chain_count_for_test() > 0; ++guard)
        f.mon.fire_tc_chains_for_test();
    REQUIRE(f.mon.tc_chain_count_for_test() == 0);

    // Every packet of a chain except the final one carries the TC bit, so a completed pair of chains shows exactly
    // two TC-clear query packets.
    auto [tc_set, tc_clear] = count_tc_queries(f.socket().sent_packets());
    REQUIRE(tc_clear == 2);
    REQUIRE(tc_set >= 2);
}
