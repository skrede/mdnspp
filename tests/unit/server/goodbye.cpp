#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <variant>
#include <algorithm>

namespace {

bool is_goodbye_packet(const std::vector<std::byte> &pkt)
{
    if(pkt.size() < 12)
        return false;

    bool has_records = false;
    bool all_zero_ttl = true;
    walk_dns_frame(std::span<const std::byte>(pkt), endpoint{}, [&](mdns_record_variant rv)
    {
        has_records = true;
        std::visit([&](const auto &rec)
        {
            if(rec.ttl != 0)
                all_zero_ttl = false;
        }, rv);
    });
    return has_records && all_zero_ttl;
}

uint32_t count_goodbye_packets(const std::vector<sent_packet> &packets)
{
    uint32_t count = 0;
    for(const auto &sp : packets)
    {
        if(is_goodbye_packet(sp.data))
            ++count;
    }
    return count;
}

void check_first_goodbye_records(const std::vector<sent_packet> &packets)
{
    auto goodbye = std::ranges::find_if(packets, [](const sent_packet &sp) { return is_goodbye_packet(sp.data); });
    if(goodbye == packets.end())
        return;
    REQUIRE(contains_record<record_ptr>(goodbye->data));
    REQUIRE(contains_record<record_srv>(goodbye->data));
    REQUIRE(contains_record<record_a>(goodbye->data));
}

}

SCENARIO("Server sends goodbye packet on stop when live", "[goodbye]")
{
    GIVEN("a server that has been advanced to live state")
    {
        server_fixture f{make_test_service()};
        f.go_live();

        WHEN("stop() is called and the posted teardown runs")
        {
            f.stop();

            THEN("a goodbye packet with TTL=0 is sent")
            {
                REQUIRE(count_goodbye_packets(f.sent()) == 1);
            }

            THEN("the goodbye packet contains PTR, SRV, A records with TTL=0")
            {
                check_first_goodbye_records(f.sent());
            }
        }
    }
}

SCENARIO("Server does NOT send goodbye when stopped during probing", "[goodbye][probing]")
{
    GIVEN("a server that has been started but not advanced past probing")
    {
        server_fixture f{make_test_service()};
        f.start();
        f.fire();

        WHEN("stop() is called during probing")
        {
            f.stop();

            THEN("no goodbye packet is sent")
            {
                REQUIRE(count_goodbye_packets(f.sent()) == 0);
            }
        }
    }
}

SCENARIO("Server skips goodbye when send_goodbye is false", "[goodbye][opt-out]")
{
    GIVEN("a server with send_goodbye=false that has been advanced to live")
    {
        service_options opts;
        opts.send_goodbye = false;
        server_fixture f{make_test_service(), std::move(opts)};
        f.go_live();

        WHEN("stop() is called")
        {
            f.stop();

            THEN("no goodbye packet is sent")
            {
                REQUIRE(count_goodbye_packets(f.sent()) == 0);
            }
        }
    }
}

SCENARIO("Goodbye sent at most once on double stop", "[goodbye][idempotent]")
{
    GIVEN("a server that has been advanced to live state")
    {
        server_fixture f{make_test_service()};
        f.go_live();

        WHEN("stop() is called twice")
        {
            f.server.stop();
            f.stop();

            THEN("exactly one goodbye packet is sent")
            {
                REQUIRE(count_goodbye_packets(f.sent()) == 1);
            }
        }
    }
}

SCENARIO("Server sends goodbye when stopped during announcing", "[goodbye][announcing]")
{
    GIVEN("a server that has completed probing but is still announcing")
    {
        service_options opts;
        opts.announce_count = 3;
        server_fixture f{make_test_service(), std::move(opts)};
        f.start();
        f.finish_probing();
        f.fire(); // second of three announcements

        WHEN("stop() is called during announcing")
        {
            f.stop();

            THEN("a goodbye packet is sent")
            {
                REQUIRE(count_goodbye_packets(f.sent()) == 1);
            }
        }
    }
}
