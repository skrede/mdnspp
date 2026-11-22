#include "inproc_bus/helpers.h"

#include "mdnspp/records.h"
#include "mdnspp/dns_name.h"
#include "mdnspp/callback_types.h"
#include "mdnspp/service_options.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <variant>
#include <optional>
#include <algorithm>
#include <string_view>
#include <system_error>

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

server_completion_handler record_ready(std::optional<std::error_code> &ready)
{
    return [&ready](std::error_code ec) { ready = ec; };
}

bool holds_srv(const std::vector<mdns_record_variant> &records, std::string_view name, uint16_t port)
{
    return std::ranges::any_of(records,
                               [name, port](const mdns_record_variant &rec)
                               {
                                   const auto *srv = std::get_if<record_srv>(&rec);
                                   return srv != nullptr && srv->name == dns_name{name} && srv->port == port;
                               });
}

void check_ready(const std::optional<std::error_code> &ready)
{
    REQUIRE(ready.has_value());
    CHECK_FALSE(*ready);
}

}

TEST_CASE("Probe conflict resolution between two servers", "[inproc][discovery]")
{
    inproc_harness h;
    bool conflict_a = false;
    bool conflict_b = false;
    std::optional<std::error_code> ready_a;
    std::optional<std::error_code> ready_b;
    std::vector<mdns_record_variant> seen;
    live_observer obs{h, record_sink(seen)};
    // RFC 6762 section 8.2.1: the SRV rdata of port 9090 sorts after 8080, so server_a loses, defers and renames.
    auto server_a = h.make_server(make_service("SharedName._http._tcp.local.", "_http._tcp.local.", "host-a.local.",
                                               8080), renaming_opts(conflict_a, "SharedName-2._http._tcp.local."));
    auto server_b = h.make_server(make_service("SharedName._http._tcp.local.", "_http._tcp.local.", "host-b.local.",
                                               9090), renaming_opts(conflict_b, "SharedName-3._http._tcp.local."));
    server_a.async_start(record_ready(ready_a));
    server_b.async_start(record_ready(ready_b));

    for(int32_t i = 0; i < 20; ++i)
        h.advance(250ms);

    CHECK(conflict_a);
    CHECK_FALSE(conflict_b);
    check_ready(ready_a);
    check_ready(ready_b);
    CHECK(holds_srv(seen, "SharedName-2._http._tcp.local.", 8080));
}
