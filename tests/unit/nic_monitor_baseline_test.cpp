#include "mdnspp/inproc/inproc_policy.h"

#include "mdnspp/basic_nic_monitor.h"
#include "mdnspp/network_interface.h"
#include "mdnspp/nic_group_options.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <algorithm>
#include <system_error>

using namespace mdnspp;
using mdnspp::testing::test_clock;
using mdnspp::inproc::inproc_bus;
using mdnspp::inproc::inproc_executor;

namespace {

network_interface make_nic(uint32_t index, std::string name, std::string ipv4)
{
    network_interface nic;
    nic.name = std::move(name);
    nic.ipv4_address = std::move(ipv4);
    nic.index = index;
    nic.is_up = true;
    return nic;
}

nic_monitor_options failing_first_options()
{
    nic_monitor_options opts;
    opts.poll_interval = std::chrono::milliseconds{100};
    opts.enumerator = [calls = int32_t{0}](std::error_code &ec) mutable
    {
        if(calls++ == 0)
        {
            ec = std::make_error_code(std::errc::network_down);
            return std::vector<network_interface>{};
        }
        ec.clear();
        return std::vector<network_interface>{make_nic(1, "nic1", "10.0.0.1"), make_nic(2, "nic2", "10.0.1.1")};
    };
    return opts;
}

}

TEST_CASE("nic_monitor reports every interface after a failed first enumeration", "[nic_monitor]")
{
    test_clock::reset();
    inproc_bus<test_clock> bus;
    inproc_executor<test_clock> executor{bus};
    basic_nic_monitor<inproc_test_policy> mon{executor, failing_first_options()};
    REQUIRE(mon.current().empty());

    std::vector<std::string> added;
    mon.on_added([&added](const network_interface &nic) { added.push_back(nic.name); });
    mon.start();
    executor.drain();
    test_clock::advance(std::chrono::milliseconds{100});
    executor.drain();

    std::ranges::sort(added);
    CHECK(added == std::vector<std::string>{"nic1", "nic2"});
    CHECK(mon.current().size() == 2);
    mon.stop();
}
