#include "mdnspp/detail/post_queue.h"

#include "mdnspp/default/default_timer.h"
#include "mdnspp/default/default_context.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <cstddef>
#include <algorithm>

namespace {

class inline_post_hook
{
public:
    explicit inline_post_hook(std::vector<int> &ran)
        : m_ran{ran}
        , m_fired{false}
    {
    }

    template <typename Queue>
    void after_swap(Queue &queue)
    {
        if(m_fired)
            return;
        m_fired = true;
        queue.post([&ran = m_ran] { ran.push_back(2); });
    }

private:
    std::vector<int> &m_ran;
    bool m_fired;
};

}

TEST_CASE("post between the swap and the flag clear still wakes the loop", "[post_queue]")
{
    std::vector<int> ran;
    std::size_t wakes = 0;
    mdnspp::detail::post_queue<inline_post_hook> queue{[&wakes] { ++wakes; }, inline_post_hook{ran}};

    queue.post([&ran] { ran.push_back(1); });
    REQUIRE(queue.drain() == 1);

    REQUIRE(wakes == 2);
    REQUIRE(queue.pending());
    REQUIRE(queue.drain() == 1);
    REQUIRE(ran == std::vector<int>{1, 2});
}

TEST_CASE("back-to-back posts coalesce into one wake", "[post_queue]")
{
    std::size_t wakes = 0;
    std::size_t ran = 0;
    mdnspp::detail::post_queue<> queue{[&wakes] { ++wakes; }};

    for(int i = 0; i < 100; ++i)
        queue.post([&ran] { ++ran; });

    REQUIRE(wakes == 1);
    REQUIRE(queue.drain() == 100);
    REQUIRE(ran == 100);
}

TEST_CASE("drain on an empty queue runs nothing and the next post wakes again", "[post_queue]")
{
    std::size_t wakes = 0;
    mdnspp::detail::post_queue<> queue{[&wakes] { ++wakes; }};

    REQUIRE(queue.drain() == 0);
    queue.post([] {});

    REQUIRE(wakes == 1);
    REQUIRE(queue.drain() == 1);
}

TEST_CASE("posts from one thread run in posting order", "[post_queue]")
{
    std::vector<int> order;
    mdnspp::detail::post_queue<> queue{[] {}};

    for(int i = 1; i <= 50; ++i)
        queue.post([&order, i] { order.push_back(i); });
    queue.drain();

    REQUIRE(order.size() == 50);
    REQUIRE(std::is_sorted(order.begin(), order.end()));
}

TEST_CASE("clear drops queued items and re-arms the wake", "[post_queue]")
{
    std::size_t wakes = 0;
    std::size_t ran = 0;
    mdnspp::detail::post_queue<> queue{[&wakes] { ++wakes; }};

    queue.post([&ran] { ++ran; });
    queue.clear();
    REQUIRE_FALSE(queue.pending());

    queue.post([&ran] { ++ran; });
    REQUIRE(wakes == 2);
    REQUIRE(queue.drain() == 1);
    REQUIRE(ran == 1);
}

TEST_CASE("restart discards stale posts and the next post still wakes the loop", "[post_queue]")
{
    mdnspp::default_context ctx;
    std::vector<int> ran;

    ctx.post([&ran] { ran.push_back(1); });
    ctx.restart();
    ctx.post([&ran] { ran.push_back(2); });
    ctx.poll_one();

    REQUIRE(ran == std::vector<int>{2});
}
