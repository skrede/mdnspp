#include "inproc_bus/helpers.h"
#include "inproc_bus/ttl_helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>

TEST_CASE("receive_ttl_minimum=255 drops TTL=254 packets", "[inproc][ttl-filter]")
{
    inproc_harness h;
    counting_observer obs{h, ttl_floor(255)};
    auto pkt = make_ptr_response("TtlTest._http._tcp.local.", "_http._tcp.local.", "ttltest.local.", 9000);
    endpoint from{"192.168.1.50", 5353};

    obs.deliver(from, pkt, uint8_t{254});
    REQUIRE(obs.records == 0u);

    obs.deliver(from, pkt, uint8_t{255});
    REQUIRE(obs.records >= 1u);
}

TEST_CASE("receive_ttl_minimum=0 accepts all TTL values", "[inproc][ttl-filter]")
{
    inproc_harness h;
    counting_observer obs{h, ttl_floor(0)};
    auto pkt = make_ptr_response("TtlMin0._http._tcp.local.", "_http._tcp.local.", "ttlmin0.local.", 9001);

    obs.deliver({"192.168.1.51", 5353}, pkt, uint8_t{0});
    REQUIRE(obs.records >= 1u);
}

TEST_CASE("receive_ttl_minimum=1 accepts TTL=1, drops TTL=0", "[inproc][ttl-filter]")
{
    inproc_harness h;
    counting_observer obs1{h, ttl_floor(1)};
    counting_observer obs2{h, ttl_floor(1)};
    endpoint from{"192.168.1.52", 5353};
    auto pkt_ttl1 = make_ptr_response("TtlOne1._http._tcp.local.", "_http._tcp.local.", "ttlone1.local.", 9002);
    auto pkt_ttl0 = make_ptr_response("TtlZero0._http._tcp.local.", "_http._tcp.local.", "ttlzero0.local.", 9003);

    obs1.deliver(from, pkt_ttl1, uint8_t{1});
    REQUIRE(obs1.records >= 1u);

    obs2.deliver(from, pkt_ttl0, uint8_t{0});
    REQUIRE(obs2.records == 0u);
}
