#include "netns/probe_defender.h"

#include "support/netns.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <cstdint>

using mdnspp::test_support::require_netns_harness;

namespace {

void require_defense_to_reach_d0(const defense_family &family)
{
    for(uint32_t suffix = 100; suffix <= 115; ++suffix)
    {
        const std::string source = family.source_prefix + std::to_string(suffix);
        INFO("defender source " << source);
        const defense_round round = run_defense_round(family, source);
        CHECK(round.probe_heard);
        CHECK(round.d0_conflict);
        CHECK_FALSE(round.d1_conflict);
    }
}

}

TEST_CASE("a defense to a grouped server's IPv4 probe reaches the server that probed on that link",
          "[netns][probe_defense]")
{
    require_netns_harness();
    require_defense_to_reach_d0(defense_family{AF_INET, "224.0.0.251", "0.0.0.0", "10.20.0."});
}

TEST_CASE("a defense to a grouped server's IPv6 probe reaches the server that probed on that link",
          "[netns][probe_defense]")
{
    require_netns_harness();
    require_defense_to_reach_d0(defense_family{AF_INET6, "ff02::fb", "::", "fd20:0::"});
}
