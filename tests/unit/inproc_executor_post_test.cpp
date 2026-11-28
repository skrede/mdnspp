#include "mdnspp/inproc/inproc_bus.h"
#include "mdnspp/inproc/inproc_policy.h"
#include "mdnspp/inproc/inproc_executor.h"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <chrono>
#include <future>
#include <thread>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <functional>

using namespace std::chrono_literals;

using mdnspp::inproc_policy;
using mdnspp::inproc::inproc_bus;
using mdnspp::inproc::inproc_executor;

namespace {

constexpr std::size_t poster_count = 4;
constexpr uint32_t posts_per_thread = 1000;

using records = std::array<std::vector<uint32_t>, poster_count>;

void post_sequence(inproc_executor<> &ex, records &out, std::size_t poster)
{
    for(uint32_t i = 0; i < posts_per_thread; ++i)
        inproc_policy::post(ex, [&out, poster, i] { out[poster].push_back(i); });
}

std::size_t step_until(inproc_executor<> &ex, const records &out, std::size_t total)
{
    const auto deadline = std::chrono::steady_clock::now() + 20s;
    std::size_t ran = 0;
    while(ran < total && std::chrono::steady_clock::now() < deadline)
    {
        if(!ex.step())
            std::this_thread::yield();
        ran = 0;
        for(const std::vector<uint32_t> &seq : out)
            ran += seq.size();
    }
    return ran;
}

void run_then_signal(inproc_executor<> &ex, std::promise<void> &ended)
{
    ex.run();
    ended.set_value();
}

}

TEST_CASE("posts from several threads each run once in posting order per thread", "[inproc_executor][thread]")
{
    inproc_bus<> bus;
    inproc_executor<> ex{bus};
    records out;
    std::vector<std::thread> posters;
    for(std::size_t t = 0; t < poster_count; ++t)
        posters.emplace_back(post_sequence, std::ref(ex), std::ref(out), t);
    const std::size_t ran = step_until(ex, out, poster_count * posts_per_thread);
    for(std::thread &t : posters)
        t.join();

    REQUIRE(ran == poster_count * posts_per_thread);
    std::vector<uint32_t> expected;
    for(uint32_t i = 0; i < posts_per_thread; ++i)
        expected.push_back(i);
    for(const std::vector<uint32_t> &seq : out)
        CHECK(seq == expected);
}

TEST_CASE("stop from another thread ends run after a cross-thread post ran", "[inproc_executor][thread]")
{
    inproc_bus<> bus;
    inproc_executor<> ex{bus};
    std::promise<void> ran;
    std::promise<void> ended;
    std::future<void> ran_future = ran.get_future();
    std::future<void> ended_future = ended.get_future();
    std::thread worker{run_then_signal, std::ref(ex), std::ref(ended)};

    inproc_policy::post(ex, [&ran] { ran.set_value(); });
    const bool posted_ran = ran_future.wait_for(10s) == std::future_status::ready;
    ex.stop();
    const bool run_ended = ended_future.wait_for(10s) == std::future_status::ready;
    worker.join();

    CHECK(posted_ran);
    CHECK(run_ended);
}
