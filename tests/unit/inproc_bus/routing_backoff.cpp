#include "inproc_bus/helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <cstddef>
#include <cstdint>
#include <variant>

namespace {

mdns_options backoff_opts()
{
    mdns_options opts;
    opts.initial_interval = 1000ms;
    opts.max_interval = 8000ms;
    opts.backoff_multiplier = 2.0;
    return opts;
}

// The observer sees no questions, so the distinct arrival times of the server's PTR answers stand in for the
// monitor's query times.
observer_options ptr_answer_times(std::vector<test_clock::time_point> &times)
{
    observer_options opts;
    opts.on_record = [&times](const endpoint &, const mdns_record_variant &rec)
    {
        if(std::holds_alternative<record_ptr>(rec) && (times.empty() || test_clock::now() != times.back()))
            times.push_back(test_clock::now());
    };
    return opts;
}

bool intervals_non_decreasing(const std::vector<test_clock::time_point> &times)
{
    for(std::size_t i = 2; i < times.size(); ++i)
        if(times[i] - times[i - 1] < times[i - 1] - times[i - 2])
            return false;
    return true;
}

}

TEST_CASE("Query backoff convergence", "[inproc][routing]")
{
    inproc_harness h;
    live_server srv{h, make_service("BackoffServer._http._tcp.local.", "_http._tcp.local.", "backoff.local.", 7777)};
    std::vector<test_clock::time_point> query_times;
    live_observer obs{h, ptr_answer_times(query_times)};
    live_monitor monitor{h, "_http._tcp.local.", discover_opts(), backoff_opts()};

    // Intervals 1, 2, 4, 8 and 8 s fit in 24 one-second steps.
    for(int32_t i = 0; i < 24; ++i)
        h.advance(1000ms);

    REQUIRE(query_times.size() >= 3u);
    CHECK(intervals_non_decreasing(query_times));
    obs.observer.stop();
    h.executor.drain();
}
