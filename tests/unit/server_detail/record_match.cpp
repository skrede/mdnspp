#include "helpers.h"

#include "mdnspp/detail/server_record_match.h"

#include <catch2/catch_test_macros.hpp>

namespace {

void check_srv_ownership(const service_info &info)
{
    SECTION("identical SRV matches and does not conflict")
    {
        auto srv = make_srv("MyApp._http._tcp.local.", 8080, "myhost.local.");
        CHECK(record_matches_ours(srv, info));
        CHECK_FALSE(record_conflicts_ours(srv, info));
    }

    SECTION("SRV with our name but different rdata conflicts (RFC 6762 section 9)")
    {
        auto srv = make_srv("MyApp._http._tcp.local.", 9999, "otherhost.local.");
        CHECK_FALSE(record_matches_ours(srv, info));
        CHECK(record_conflicts_ours(srv, info));
    }

    SECTION("SRV for a foreign name neither matches nor conflicts")
    {
        auto srv = make_srv("Other._http._tcp.local.", 8080, "myhost.local.");
        CHECK_FALSE(record_matches_ours(srv, info));
        CHECK_FALSE(record_conflicts_ours(srv, info));
    }
}

}

TEST_CASE("record_matches_ours and record_conflicts_ours", "[server_known_answer]")
{
    auto info = make_test_info();
    check_srv_ownership(info);

    SECTION("A record at our hostname with different address conflicts")
    {
        CHECK(record_conflicts_ours(make_a("myhost.local.", "10.0.0.99"), info));
    }

    SECTION("PTR records are shared and never conflict")
    {
        CHECK_FALSE(record_conflicts_ours(make_ptr("_http._tcp.local.", "Other._http._tcp.local."), info));
    }
}
