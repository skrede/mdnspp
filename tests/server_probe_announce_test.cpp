// tests/server_probe_announce_test.cpp
// Unit tests for detail::probe_announce_state and state transition functions.

#include "mdnspp/detail/server_probe_announce.h"

#include <catch2/catch_test_macros.hpp>

using namespace mdnspp::detail;

TEST_CASE("begin_probing resets state", "[server_probe_announce]")
{
    probe_announce_state s;
    s.state = server_state::live;
    s.probe_count = 5;

    begin_probing(s);

    CHECK(s.state == server_state::probing);
    CHECK(s.probe_count == 0);
}

TEST_CASE("advance_probe increments count", "[server_probe_announce]")
{
    probe_announce_state s;
    begin_probing(s);

    SECTION("returns true when more probes needed")
    {
        CHECK(advance_probe(s));
        CHECK(s.probe_count == 1);
        CHECK(advance_probe(s));
        CHECK(s.probe_count == 2);
    }

    SECTION("returns false when count reaches 3")
    {
        advance_probe(s);
        advance_probe(s);
        CHECK_FALSE(advance_probe(s));
        CHECK(s.probe_count == 3);
    }
}

TEST_CASE("should_send_probe", "[server_probe_announce]")
{
    probe_announce_state s;
    begin_probing(s);

    CHECK(should_send_probe(s));
    advance_probe(s);
    advance_probe(s);
    advance_probe(s);
    CHECK_FALSE(should_send_probe(s));
}

TEST_CASE("probing_complete returns true at count >= 3", "[server_probe_announce]")
{
    probe_announce_state s;
    begin_probing(s);

    CHECK_FALSE(probing_complete(s));
    advance_probe(s);
    advance_probe(s);
    advance_probe(s);
    CHECK(probing_complete(s));
}

TEST_CASE("begin_announcing transitions state", "[server_probe_announce]")
{
    probe_announce_state s;
    begin_probing(s);
    advance_probe(s);
    advance_probe(s);
    advance_probe(s);

    begin_announcing(s);

    CHECK(s.state == server_state::announcing);
    CHECK(s.announce_count == 0);
}

TEST_CASE("advance_announce increments and respects max", "[server_probe_announce]")
{
    probe_announce_state s;
    begin_announcing(s);

    SECTION("returns true when more needed")
    {
        CHECK(advance_announce(s, 3));
        CHECK(s.announce_count == 1);
    }

    SECTION("returns false at max count")
    {
        advance_announce(s, 2);
        CHECK_FALSE(advance_announce(s, 2));
        CHECK(s.announce_count == 2);
    }
}

TEST_CASE("should_send_announce", "[server_probe_announce]")
{
    probe_announce_state s;
    begin_announcing(s);

    CHECK(should_send_announce(s, 2));
    advance_announce(s, 2);
    advance_announce(s, 2);
    CHECK_FALSE(should_send_announce(s, 2));
}
