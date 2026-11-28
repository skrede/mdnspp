#include "probing_fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <optional>

namespace {

// A different priority yields a deterministic RFC 6762 section 8.2.1 tiebreak.
std::vector<std::byte> make_conflicting_probe(const service_info &our_info, uint8_t rdata_filler)
{
    service_info other = our_info;
    other.priority = static_cast<uint16_t>(rdata_filler);
    return build_probe_query(other);
}

service_options probing_at_once(conflict_log &log, std::optional<std::string> rename)
{
    service_options opts = on_conflict_into(log, std::move(rename));
    opts.probe_initial_delay_max = std::chrono::milliseconds{0};
    return opts;
}

void deferred_sections(server_fixture &f, const conflict_log &log)
{
    THEN("on_conflict is called with conflict_type::tiebreak_deferred")
    {
        REQUIRE(log.called);
        REQUIRE(log.type == conflict_type::tiebreak_deferred);
    }

    THEN("the probe timer is rearmed for defer delay after tiebreak loss")
    {
        REQUIRE(f.server.timer().has_pending());
    }
}

}

SCENARIO("Probe tiebreaking: loser defers and conflict_type is tiebreak_deferred", "[service_server][probe][tiebreaking]")
{
    GIVEN("a server probing with priority=0 and another probe arrives with priority=255 (ours < theirs -- we lose)")
    {
        conflict_log log;
        service_options opts = probing_at_once(log, "Renamed._http._tcp.local.");
        opts.probe_defer_delay = std::chrono::milliseconds{100};
        service_info info = make_test_info();
        info.priority = 0;
        server_fixture f{info, std::move(opts)};

        WHEN("async_start is called, probe begins, and a winning probe arrives from another host")
        {
            f.start();
            f.fire();
            // Their SRV rdata is lexicographically greater, so they win and we defer.
            f.inject(endpoint{"192.168.1.99", 5353}, make_conflicting_probe(info, 255));
            deferred_sections(f, log);
        }
    }
}

SCENARIO("Probe tiebreaking: winner (ours > theirs) does NOT defer", "[service_server][probe][tiebreaking][win]")
{
    GIVEN("a server probing with priority=255 and another probe arrives with priority=0 (ours > theirs -- we win)")
    {
        conflict_log log;
        service_info info = make_test_info();
        info.priority = 255;
        server_fixture f{info, probing_at_once(log, std::nullopt)};

        WHEN("async_start is called, probe begins, and a losing probe arrives from another host")
        {
            f.start();
            f.fire();
            f.inject(endpoint{"192.168.1.99", 5353}, make_conflicting_probe(info, 0));

            THEN("on_conflict is NOT called (we won)")
            {
                REQUIRE_FALSE(log.called);
            }
        }
    }
}

SCENARIO("A simultaneous probe with an identical record set is a tie, not a conflict",
         "[service_server][probe][tiebreaking][tie]")
{
    GIVEN("a server currently probing")
    {
        conflict_log log;
        server_fixture f{make_test_info(), probing_at_once(log, std::nullopt)};

        WHEN("a probe with the exact same proposed record set arrives (e.g. our own loopback)")
        {
            f.start();
            f.fire();
            // RFC 6762 section 8.2.1: identical record sets are not a conflict. This also covers our own
            // looped-back probe (message ID is always 0).
            f.inject(endpoint{"192.168.1.10", 5353}, build_probe_query(make_test_info()));

            THEN("on_conflict is NOT called (exact tie)")
            {
                REQUIRE_FALSE(log.called);
            }
        }
    }
}
