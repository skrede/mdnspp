// basic_nic_monitor unit tests.
//
// The OS change-notification backends (netlink, nw_path_monitor,
// NotifyIpInterfaceChange) cannot run deterministically in CI. These tests
// exercise the diff/apply logic through the nic_monitor_options::enumerator
// seam, which forces the polling path and substitutes a test-controlled
// interface list for enumerate_interfaces().

#include "mdnspp/inproc/inproc_policy.h"

#include "mdnspp/nic_group_options.h"
#include "mdnspp/basic_nic_monitor.h"
#include "mdnspp/network_interface.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <memory>
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

struct monitor_fixture
{
    monitor_fixture()
    {
        test_clock::reset();
    }

    nic_monitor_options make_opts()
    {
        nic_monitor_options opts;
        opts.poll_interval = std::chrono::milliseconds{100};
        opts.enumerator = [nics = nics](std::error_code &ec)
        {
            ec.clear();
            return *nics;
        };
        return opts;
    }

    void advance(std::chrono::milliseconds d)
    {
        test_clock::advance(d);
        executor.drain();
    }

    inproc_bus<test_clock> bus;
    inproc_executor<test_clock> executor{bus};
    std::shared_ptr<std::vector<network_interface>> nics{
        std::make_shared<std::vector<network_interface>>()};
};

}

TEST_CASE("nic_monitor takes the initial snapshot from the custom enumerator", "[nic_monitor]")
{
    monitor_fixture f;
    f.nics->push_back(make_nic(1, "nic1", "10.0.0.1"));
    f.nics->push_back(make_nic(2, "nic2", "10.0.1.1"));

    basic_nic_monitor<inproc_test_policy> mon{f.executor, f.make_opts()};

    auto snapshot = mon.current();
    REQUIRE(snapshot.size() == 2);
    REQUIRE(std::ranges::find_if(snapshot, [](const auto &n) { return n.name == "nic1"; }) != snapshot.end());
    REQUIRE(std::ranges::find_if(snapshot, [](const auto &n) { return n.name == "nic2"; }) != snapshot.end());
}

TEST_CASE("nic_monitor fires on_added when an interface appears", "[nic_monitor]")
{
    monitor_fixture f;
    f.nics->push_back(make_nic(1, "nic1", "10.0.0.1"));

    basic_nic_monitor<inproc_test_policy> mon{f.executor, f.make_opts()};

    std::vector<std::string> added;
    std::vector<std::string> removed;
    mon.on_added([&](const network_interface &nic) { added.push_back(nic.name); });
    mon.on_removed([&](const network_interface &nic) { removed.push_back(nic.name); });

    mon.start();
    f.executor.drain();

    f.nics->push_back(make_nic(2, "nic2", "10.0.1.1"));
    f.advance(std::chrono::milliseconds{100});
    f.executor.drain();

    REQUIRE(added == std::vector<std::string>{"nic2"});
    REQUIRE(removed.empty());
    REQUIRE(mon.current().size() == 2);

    mon.stop();
}

TEST_CASE("nic_monitor fires on_removed when an interface disappears", "[nic_monitor]")
{
    monitor_fixture f;
    f.nics->push_back(make_nic(1, "nic1", "10.0.0.1"));
    f.nics->push_back(make_nic(2, "nic2", "10.0.1.1"));

    basic_nic_monitor<inproc_test_policy> mon{f.executor, f.make_opts()};

    std::vector<std::string> removed;
    mon.on_removed([&](const network_interface &nic) { removed.push_back(nic.name); });

    mon.start();
    f.executor.drain();

    std::erase_if(*f.nics, [](const auto &n) { return n.index == 1; });
    f.advance(std::chrono::milliseconds{100});
    f.executor.drain();

    REQUIRE(removed == std::vector<std::string>{"nic1"});
    REQUIRE(mon.current().size() == 1);

    mon.stop();
}

TEST_CASE("nic_monitor treats an address change as remove followed by add", "[nic_monitor]")
{
    monitor_fixture f;
    f.nics->push_back(make_nic(1, "nic1", "10.0.0.1"));

    basic_nic_monitor<inproc_test_policy> mon{f.executor, f.make_opts()};

    std::vector<std::pair<std::string, std::string>> events; // (kind, ipv4)
    mon.on_added([&](const network_interface &nic) { events.emplace_back("added", nic.ipv4_address); });
    mon.on_removed([&](const network_interface &nic) { events.emplace_back("removed", nic.ipv4_address); });

    mon.start();
    f.executor.drain();

    f.nics->front().ipv4_address = "10.0.0.2";
    f.advance(std::chrono::milliseconds{100});
    f.executor.drain();

    REQUIRE(events.size() == 2);
    REQUIRE(events[0] == std::pair<std::string, std::string>{"removed", "10.0.0.1"});
    REQUIRE(events[1] == std::pair<std::string, std::string>{"added", "10.0.0.2"});

    mon.stop();
}

TEST_CASE("nic_monitor stop is idempotent and suppresses further events", "[nic_monitor]")
{
    monitor_fixture f;
    f.nics->push_back(make_nic(1, "nic1", "10.0.0.1"));

    basic_nic_monitor<inproc_test_policy> mon{f.executor, f.make_opts()};

    std::vector<std::string> added;
    mon.on_added([&](const network_interface &nic) { added.push_back(nic.name); });

    mon.start();
    f.executor.drain();

    mon.stop();
    mon.stop();

    f.nics->push_back(make_nic(2, "nic2", "10.0.1.1"));
    f.advance(std::chrono::milliseconds{200});
    f.executor.drain();

    REQUIRE(added.empty());
}
