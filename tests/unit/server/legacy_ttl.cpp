#include "fixture.h"
#include "query_helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>

namespace {

recv_metadata legacy_query_meta(server_fixture &f, std::optional<uint8_t> ttl)
{
    recv_metadata meta = f.server.socket().default_metadata();
    meta.sender = endpoint{"192.168.1.20", 40000};
    meta.ttl = ttl;
    return meta;
}

}

TEST_CASE("a legacy query sent with TTL 1 is answered with default options",
          "[service_server][legacy_unicast][ttl-filter]")
{
    server_fixture f;
    f.go_live();
    f.clear_sent();
    f.server.socket().inject_receive(legacy_query_meta(f, uint8_t{1}), make_ptr_query("_http._tcp.local."));

    CHECK(sent_to(f.sent(), endpoint{"192.168.1.20", 40000}));
}

TEST_CASE("a legacy query of unknown TTL is answered when unknown TTLs are rejected",
          "[service_server][legacy_unicast][ttl-filter]")
{
    server_fixture f{make_test_info(), {}, mdns_options{.unknown_ttl_policy = ttl_unknown_policy::reject}};
    f.go_live();
    f.clear_sent();
    f.server.socket().inject_receive(legacy_query_meta(f, std::nullopt), make_ptr_query("_http._tcp.local."));

    CHECK(sent_to(f.sent(), endpoint{"192.168.1.20", 40000}));
}
