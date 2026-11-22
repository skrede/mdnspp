#include "inproc_bus/helpers.h"
#include "inproc_bus/query_sniffer.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <vector>
#include <cstddef>
#include <cstdint>

namespace {

mdns_options backoff_opts()
{
    mdns_options opts;
    opts.initial_interval = 1000ms;
    opts.max_interval = 8000ms;
    opts.backoff_multiplier = 2.0;
    return opts;
}

std::vector<std::chrono::milliseconds> intervals(const std::vector<test_clock::time_point> &times)
{
    std::vector<std::chrono::milliseconds> spacing;
    for(std::size_t i = 1; i < times.size(); ++i)
        spacing.push_back(std::chrono::duration_cast<std::chrono::milliseconds>(times[i] - times[i - 1]));
    return spacing;
}

}

TEST_CASE("Query backoff convergence", "[inproc][routing]")
{
    inproc_harness h;
    live_server srv{h, make_service("BackoffServer._http._tcp.local.", "_http._tcp.local.", "backoff.local.", 7777)};
    query_sniffer sniffer{h};
    live_monitor monitor{h, "_http._tcp.local.", discover_opts(), backoff_opts()};

    for(int32_t i = 0; i < 24; ++i)
        h.advance(1000ms);

    REQUIRE(sniffer.times.size() == 6u);
    CHECK(intervals(sniffer.times) == std::vector<std::chrono::milliseconds>{1000ms, 2000ms, 4000ms, 8000ms, 8000ms});
    h.executor.drain();
}
