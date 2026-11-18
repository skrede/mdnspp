#include "mdnspp/default/default_timer.h"
#include "mdnspp/default/default_context.h"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <future>
#include <thread>
#include <cstdint>

#if defined(__has_feature)
#  define MDNSPP_TEST_HAS_FEATURE(x) __has_feature(x)
#else
#  define MDNSPP_TEST_HAS_FEATURE(x) 0
#endif

using namespace std::chrono_literals;

namespace {

#if defined(__SANITIZE_THREAD__) || MDNSPP_TEST_HAS_FEATURE(thread_sanitizer)
constexpr uint32_t iterations = 20000;
#else
constexpr uint32_t iterations = 200000;
#endif

void spin_for(uint32_t iteration)
{
    const uint32_t count = (iteration * 2654435761u) % 20000;
    for(volatile uint32_t k = 0; k < count; k = k + 1)
    {
    }
}

class posting_loop
{
public:
    posting_loop()
        : m_done{0}
        , m_posted{0}
        , m_thread{[this] { m_ctx.run(); }}
    {
    }

    ~posting_loop()
    {
        m_ctx.stop();
        m_thread.join();
    }

    posting_loop(const posting_loop &) = delete;
    posting_loop &operator=(const posting_loop &) = delete;

    bool round_trip(uint32_t iteration)
    {
        std::promise<void> reached;
        std::future<void> future = reached.get_future();
        m_ctx.post([this] { m_done.fetch_add(1, std::memory_order_relaxed); });
        spin_for(iteration);
        m_ctx.post([this, p = std::move(reached)]() mutable {
            m_done.fetch_add(1, std::memory_order_relaxed);
            p.set_value();
        });
        m_posted += 2;
        return future.wait_for(2s) == std::future_status::ready;
    }

    uint64_t posted() const { return m_posted; }
    uint64_t done() const { return m_done.load(std::memory_order_relaxed); }

private:
    mdnspp::default_context m_ctx;
    std::atomic<uint64_t> m_done;
    uint64_t m_posted;
    std::thread m_thread;
};

}

TEST_CASE("cross-thread posts always execute", "[stress]")
{
    posting_loop loop;

    for(uint32_t i = 0; i < iterations; ++i)
    {
        if(!loop.round_trip(i))
            FAIL("post stranded at iteration " << i << ": posted=" << loop.posted()
                                               << " done=" << loop.done());
    }

    REQUIRE(loop.done() == loop.posted());
}
