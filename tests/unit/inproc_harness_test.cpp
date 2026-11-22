#include "mdnspp/inproc/inproc_harness.h"

#include "mdnspp/service_info.h"
#include "mdnspp/service_options.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <system_error>

using mdnspp::inproc::inproc_harness;

namespace {

mdnspp::service_info harness_service()
{
    mdnspp::service_info info;
    info.service_name = "Harness._http._tcp.local.";
    info.service_type = "_http._tcp.local.";
    info.hostname = "harness.local.";
    info.port = 8080;
    info.address_ipv4 = "192.168.1.1";
    return info;
}

mdnspp::service_options with_probes(uint8_t probe_count)
{
    mdnspp::service_options opts;
    opts.probe_count = probe_count;
    return opts;
}

std::optional<std::error_code> outcome_after_advance_to_live(uint8_t probe_count)
{
    inproc_harness h;
    std::optional<std::error_code> outcome;
    auto server = h.make_server(harness_service(), with_probes(probe_count));
    server.async_start([&outcome](std::error_code ec) { outcome = ec; });
    h.advance_to_live(server, with_probes(probe_count));
    // A copy, so the cancellation the server's destructor reports does not reach the caller's value.
    return std::optional<std::error_code>{outcome};
}

}

TEST_CASE("advance_to_live brings a server with five probes live", "[inproc][harness]")
{
    const std::optional<std::error_code> outcome = outcome_after_advance_to_live(5);
    REQUIRE(outcome.has_value());
    CHECK_FALSE(*outcome);
}

TEST_CASE("advance_to_live brings a server with three probes live", "[inproc][harness]")
{
    const std::optional<std::error_code> outcome = outcome_after_advance_to_live(3);
    REQUIRE(outcome.has_value());
    CHECK_FALSE(*outcome);
}

TEST_CASE("advance_to_live brings a server with one probe live", "[inproc][harness]")
{
    const std::optional<std::error_code> outcome = outcome_after_advance_to_live(1);
    REQUIRE(outcome.has_value());
    CHECK_FALSE(*outcome);
}
