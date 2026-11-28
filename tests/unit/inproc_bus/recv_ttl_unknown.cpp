#include "inproc_bus/helpers.h"
#include "inproc_bus/ttl_helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <optional>

TEST_CASE("nullopt TTL with ttl_unknown_policy::accept passes packet", "[inproc][ttl-filter][optional-ttl]")
{
    inproc_harness h;
    counting_observer obs{h, ttl_floor(255, ttl_unknown_policy::accept)};
    auto pkt = make_ptr_response("TtlOptAccept._http._tcp.local.", "_http._tcp.local.", "ttloptaccept.local.", 9010);

    obs.deliver({"192.168.1.60", 5353}, pkt, std::nullopt);
    REQUIRE(obs.records == ptr_response_records);
}

TEST_CASE("nullopt TTL with ttl_unknown_policy::reject drops packet", "[inproc][ttl-filter][optional-ttl]")
{
    inproc_harness h;
    counting_observer obs{h, ttl_floor(255, ttl_unknown_policy::reject)};
    auto pkt = make_ptr_response("TtlOptReject._http._tcp.local.", "_http._tcp.local.", "ttloptreject.local.", 9011);

    obs.deliver({"192.168.1.61", 5353}, pkt, std::nullopt);
    REQUIRE(obs.records == 0u);
}
