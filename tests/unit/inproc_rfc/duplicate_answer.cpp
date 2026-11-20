#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

namespace {

service_options no_meta_queries()
{
    service_options opts;
    opts.respond_to_meta_queries = false;
    return opts;
}

struct duplicate_fixture
{
    inproc_harness h;
    int32_t found_a;
    int32_t found_b;
    live_server live;
    inproc_monitor monitor_a;
    inproc_monitor monitor_b;

    duplicate_fixture()
        : h{}
        , found_a{0}
        , found_b{0}
        , live{h, make_service("DupServer._http._tcp.local.", "_http._tcp.local.", "dupserver.local.", 9100),
               no_meta_queries(), fast_response_opts()}
        , monitor_a{h.make_monitor(count_found(found_a), {}, fast_scheduler_opts())}
        , monitor_b{h.make_monitor(count_found(found_b), {}, fast_scheduler_opts())}
    {
        monitor_a.watch("_http._tcp.local.");
        monitor_b.watch("_http._tcp.local.");
        monitor_a.async_start();
        monitor_b.async_start();
        h.executor.drain();
    }
};

}

// RFC 6762 section 7.4: a querier that sees a multicast response to its own or another querier's query must not
// report the same service twice. Both monitors query on their 200 ms scheduler tick and receive the same multicast
// response 1 ms later.
TEST_CASE("Duplicate answer suppression across queriers", "[inproc][rfc]")
{
    duplicate_fixture f;

    f.h.advance(200ms);
    f.h.advance(10ms);
    CHECK(f.found_a == 1);
    CHECK(f.found_b == 1);

    f.h.advance(400ms);
    CHECK(f.found_a == 1);
    CHECK(f.found_b == 1);
}
