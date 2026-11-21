#include "inproc_bus/helpers.h"

#include "mdnspp/service_options.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <cstdint>
#include <utility>
#include <optional>
#include <string_view>

namespace {

service_options renaming_opts(bool &conflicted, std::string rename)
{
    service_options opts;
    opts.on_conflict = [&conflicted, rename = std::move(rename)](std::string_view, uint32_t, conflict_type)
        -> std::optional<std::string>
    {
        conflicted = true;
        return rename;
    };
    return opts;
}

}

TEST_CASE("Probe conflict resolution between two servers", "[inproc][discovery]")
{
    inproc_harness h;
    bool conflict_a = false;
    bool conflict_b = false;
    // Same name, different ports: the RFC 6762 section 8.2 tiebreak on the SRV rdata makes one server defer and
    // re-probe.
    auto server_a = h.make_server(make_service("SharedName._http._tcp.local.", "_http._tcp.local.", "host-a.local.",
                                               8080), renaming_opts(conflict_a, "SharedName-2._http._tcp.local."));
    auto server_b = h.make_server(make_service("SharedName._http._tcp.local.", "_http._tcp.local.", "host-b.local.",
                                               9090), renaming_opts(conflict_b, "SharedName-3._http._tcp.local."));
    server_a.async_start();
    server_b.async_start();

    // 5 s covers the default 1 s probe_defer_delay and the re-probe after it.
    for(int32_t i = 0; i < 20; ++i)
        h.advance(250ms);

    CHECK((conflict_a || conflict_b));
}
