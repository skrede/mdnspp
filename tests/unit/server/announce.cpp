#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <vector>
#include <cstddef>
#include <utility>
#include <algorithm>
#include <string_view>
#include <system_error>

namespace {

constexpr std::size_t probe_packets = 3;

service_options three_announcements()
{
    service_options opts;
    opts.announce_count = 3;
    opts.announce_interval = std::chrono::milliseconds(500);
    opts.respond_to_meta_queries = false;
    return opts;
}

void check_announcements(server_fixture &f)
{
    REQUIRE(f.sent().size() == probe_packets + 3);
    for(std::size_t i = probe_packets; i < f.sent().size(); ++i)
    {
        REQUIRE(f.sent()[i].data.size() >= 4);
        REQUIRE(flags_of(f.sent()[i]) == 0x8400);
        REQUIRE(f.sent()[i].dest == mdns_group());
    }
}

service_options recording_errors(std::vector<std::error_code> &codes, std::vector<std::string> &msgs)
{
    service_options opts;
    opts.respond_to_meta_queries = false;
    opts.on_error = [&codes, &msgs](std::error_code ec, std::string_view msg)
    {
        codes.push_back(ec);
        msgs.push_back(std::string(msg));
    };
    return opts;
}

}

SCENARIO("announcement burst sends announce_count announcements", "[service_server][announcing]")
{
    GIVEN("a service_server with announce_count=3")
    {
        server_fixture f{make_test_info(), three_announcements()};

        WHEN("probing completes and announcements are sent")
        {
            f.start();
            f.finish_probing();
            // The first announcement goes out without a timer fire.
            REQUIRE(f.sent().size() == probe_packets + 1);
            f.fire();
            REQUIRE(f.sent().size() == probe_packets + 2);
            f.fire();

            THEN("3 announcements were sent total")
            {
                check_announcements(f);
            }
        }
    }
}

SCENARIO("Server invokes on_error with invalid_ipv4_address when address encoding fails",
         "[service_server][on_error][address_encoding]")
{
    GIVEN("a service_server with an invalid IPv4 address and an on_error handler")
    {
        std::vector<std::error_code> error_codes;
        std::vector<std::string> error_msgs;
        service_info info = make_test_info();
        info.address_ipv4 = "999.1.2.3";
        server_fixture f{std::move(info), recording_errors(error_codes, error_msgs)};
        f.go_live();

        THEN("on_error was invoked at least once with invalid_ipv4_address")
        {
            REQUIRE_FALSE(error_codes.empty());
            auto expected = make_error_code(mdnspp::mdns_error::invalid_ipv4_address);
            REQUIRE(std::ranges::find(error_codes, expected) != error_codes.end());
        }
    }
}
