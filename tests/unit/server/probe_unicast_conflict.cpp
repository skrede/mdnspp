#include "probing_fixture.h"

#include "gate/metadata.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>

TEST_CASE("a probing server detects a conflict that a defender answers by unicast",
          "[service_server][conflict][qu-window]")
{
    const uint32_t loopback = index_of_127_0_0_1();
    conflict_log log;
    server_fixture f{make_test_info(), on_conflict_into(log, "Renamed._http._tcp.local.")};
    f.start();
    f.fire();
    REQUIRE_FALSE(f.sent().empty());

    const recv_metadata unicast =
        arriving(f.server.socket(), endpoint{"127.0.0.2", 5353}, address_of("127.0.0.1"), loopback);
    f.server.socket().inject_receive(unicast, make_conflict_response(test_info_on_port(9999)));
    f.ex.drain_posted();

    CHECK(log.called);
}
