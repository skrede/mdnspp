#include "netns/bound_peers.h"

#include "support/netns.h"

#include "mdnspp/basic_service_server.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <cstddef>

using mdnspp::test_support::require_netns_harness;

namespace {

std::size_t probe_records_seen_on_d0(const std::string &group)
{
    mdnspp::default_context ctx;
    recording_observer observer{ctx, bound_to("d0", group)};
    mdnspp::basic_service_server<mdnspp::default_policy> server{ctx, attribution_service(), mdnspp::service_options{},
                                                                bound_to("d0", group)};
    server.async_start();
    run_for(ctx, std::chrono::milliseconds{600});
    return observer.senders.size();
}

}

TEST_CASE("a peer bound to an interface receives an IPv4 query another peer on this host sent there",
          "[netns][attribution]")
{
    require_netns_harness();
    CHECK(probe_records_seen_on_d0("224.0.0.251") > 0);
}

TEST_CASE("a peer bound to an interface receives an IPv6 query another peer on this host sent there",
          "[netns][attribution]")
{
    require_netns_harness();
    CHECK(probe_records_seen_on_d0("ff02::fb") > 0);
}
