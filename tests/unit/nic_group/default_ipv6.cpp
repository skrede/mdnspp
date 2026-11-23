#include "support/skip_or_fail.h"

#include "mdnspp/defaults.h"
#include "mdnspp/ip_address.h"
#include "mdnspp/network_interface.h"
#include "mdnspp/nic_group_options.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>
#include <utility>
#include <optional>
#include <string_view>
#include <system_error>

namespace {

std::optional<mdnspp::network_interface> ipv6_only_loopback()
{
    std::error_code ec;
    for(mdnspp::network_interface nic : mdnspp::enumerate_interfaces(ec))
    {
        std::erase_if(nic.addresses, [](const mdnspp::ip_network &net)
        {
            return net.address.family != mdnspp::address_family::ipv6;
        });
        if(nic.is_loopback && nic.is_up && !nic.addresses.empty())
            return nic;
    }
    return std::nullopt;
}

}

TEST_CASE("a default-policy nic_group starts on an IPv6-only interface", "[nic_group][family][native]")
{
    const std::optional<mdnspp::network_interface> loopback = ipv6_only_loopback();
    if(!loopback)
        mdnspp::test_support::skip_or_fail("the loopback interface has no IPv6 address");

    std::vector<std::string> errors;
    mdnspp::nic_group_options grp_opts;
    grp_opts.monitor_opts.enumerator = [nic = *loopback](std::error_code &ec)
    {
        ec.clear();
        return std::vector<mdnspp::network_interface>{nic};
    };
    grp_opts.on_error = [&errors](const mdnspp::network_interface &, std::error_code ec, std::string_view context)
    {
        errors.push_back(std::string(context) + ": " + ec.message());
    };

    mdnspp::context ctx;
    std::vector<mdnspp::monitor_options> monitors(1);
    mdnspp::nic_group<mdnspp::basic_service_monitor> grp{ctx, std::move(grp_opts), std::move(monitors)};
    REQUIRE_NOTHROW(grp.start());
    CHECK(errors.empty());
    grp.stop();
}
