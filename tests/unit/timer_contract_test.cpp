#include "mdnspp/inproc/inproc_bus.h"
#include "mdnspp/inproc/inproc_timer.h"
#include "mdnspp/inproc/inproc_executor.h"

#include "mdnspp/testing/mock_timer.h"
#include "mdnspp/testing/test_clock.h"
#include "mdnspp/testing/mock_executor.h"

#include "mdnspp/default/default_timer.h"

#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_template_test_macros.hpp>

#include <chrono>
#include <memory>
#include <vector>
#include <system_error>

using namespace std::chrono_literals;
using mdnspp::testing::test_clock;
using completions = std::vector<std::error_code>;

namespace {

const std::error_code canceled = std::make_error_code(std::errc::operation_canceled);

struct default_rig
{
    using timer_type = mdnspp::default_timer;

    default_rig()
        : ctx()
        , timer(std::make_unique<timer_type>(ctx))
    {
    }

    void fire() { ctx.fire_expired_timers(); }

    mdnspp::default_context ctx;
    std::unique_ptr<timer_type> timer;
};

struct mock_rig
{
    using timer_type = mdnspp::testing::mock_timer;

    mock_rig()
        : ex()
        , timer(std::make_unique<timer_type>(ex))
    {
    }

    void fire() { timer->fire(); }

    mdnspp::testing::mock_executor ex;
    std::unique_ptr<timer_type> timer;
};

struct inproc_rig
{
    using timer_type = mdnspp::inproc::inproc_timer<test_clock>;

    inproc_rig()
        : bus()
        , ex(bus)
        , timer(std::make_unique<timer_type>(ex))
    {
        test_clock::reset();
    }

    void fire() { ex.drain(); }

    mdnspp::inproc::inproc_bus<test_clock> bus;
    mdnspp::inproc::inproc_executor<test_clock> ex;
    std::unique_ptr<timer_type> timer;
};

template <typename Rig, typename EndWait>
void check_rearm_from_completion(Rig &rig, EndWait end_wait)
{
    typename Rig::timer_type &timer = *rig.timer;
    completions outer;
    completions inner;
    timer.expires_after(1000ms);
    timer.async_wait(
        [&timer, &outer, &inner](std::error_code ec)
        {
            outer.push_back(ec);
            timer.expires_after(0ms);
            timer.async_wait([&inner](std::error_code inner_ec) { inner.push_back(inner_ec); });
        });
    end_wait(timer);
    CHECK(outer == completions{canceled});
    REQUIRE(timer.has_pending());
    rig.fire();
    CHECK(inner == completions{std::error_code{}});
}

template <typename Rig, typename EndWait>
void check_destroy_from_completion(Rig &rig, EndWait end_wait)
{
    completions seen;
    rig.timer->expires_after(1000ms);
    rig.timer->async_wait(
        [&rig, &seen](std::error_code ec)
        {
            seen.push_back(ec);
            rig.timer.reset();
        });
    end_wait(*rig.timer);
    CHECK(seen == completions{canceled});
    CHECK(rig.timer == nullptr);
}

}

TEMPLATE_TEST_CASE("expires_after completes a pending wait once with operation_canceled before it returns",
                   "[timer][contract]", default_rig, mock_rig, inproc_rig)
{
    TestType rig;
    completions seen;
    rig.timer->expires_after(1000ms);
    rig.timer->async_wait([&seen](std::error_code ec) { seen.push_back(ec); });
    rig.timer->expires_after(1000ms);
    CHECK(seen == completions{canceled});
    CHECK_FALSE(rig.timer->has_pending());
    rig.timer->expires_after(1000ms);
    CHECK(seen.size() == 1);
}

TEMPLATE_TEST_CASE("a handler that re-arms from the completion of expires_after leaves its own wait pending",
                   "[timer][contract]", default_rig, mock_rig, inproc_rig)
{
    TestType rig;
    check_rearm_from_completion(rig, [](auto &timer) { timer.expires_after(1000ms); });
}

TEMPLATE_TEST_CASE("a handler that re-arms from the completion of cancel leaves its own wait pending",
                   "[timer][contract]", default_rig, mock_rig, inproc_rig)
{
    TestType rig;
    check_rearm_from_completion(rig, [](auto &timer) { timer.cancel(); });
}

TEMPLATE_TEST_CASE("a handler may destroy its timer from the completion of expires_after", "[timer][contract]",
                   default_rig, mock_rig, inproc_rig)
{
    TestType rig;
    check_destroy_from_completion(rig, [](auto &timer) { timer.expires_after(1000ms); });
}

TEMPLATE_TEST_CASE("a handler may destroy its timer from the completion of cancel", "[timer][contract]", default_rig,
                   mock_rig, inproc_rig)
{
    TestType rig;
    check_destroy_from_completion(rig, [](auto &timer) { timer.cancel(); });
}
