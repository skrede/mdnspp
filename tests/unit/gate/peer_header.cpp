#include "helpers.h"

#include <catch2/generators/catch_generators.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_template_test_macros.hpp>

#include <cstdint>

TEST_CASE("a querier does not report a response with RCODE 3 and reports the valid response after it",
          "[gate][header][querier]")
{
    querier_rig rig;
    feed(rig, with_flags(service_response("Dropped"), response_flags | 0x0003));
    feed(rig, service_response("Kept"));

    CHECK(rig.reported("Dropped") == 0);
    CHECK(rig.reported("Kept") == 1);
}

TEMPLATE_TEST_CASE("a peer ignores a response with a nonzero OPCODE or RCODE and takes the valid one after it",
                   "[gate][header]", querier_rig, observer_rig, monitor_rig, discovery_rig)
{
    const uint16_t bad_bits = GENERATE(uint16_t{0x0800}, uint16_t{0x7800}, uint16_t{0x0001}, uint16_t{0x000F});
    TestType rig;
    feed(rig, with_flags(service_response("Dropped"), response_flags | bad_bits));
    feed(rig, service_response("Kept"));

    CHECK(rig.reported("Dropped") == 0);
    CHECK(rig.reported("Kept") == 1);
}

TEST_CASE("a server does not answer a query with a nonzero OPCODE or RCODE and answers the valid one after it",
          "[gate][header][server]")
{
    const uint16_t bad_bits = GENERATE(uint16_t{0x0800}, uint16_t{0x0001});
    server_rig rig;
    feed(rig, with_flags(service_query(), bad_bits));
    CHECK_FALSE(rig.peer.delay_timer().has_pending());

    feed(rig, service_query());
    CHECK(rig.peer.delay_timer().has_pending());
}
