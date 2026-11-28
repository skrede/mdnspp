#include "mdnspp/inproc/inproc_bus.h"
#include "mdnspp/inproc/inproc_timer.h"
#include "mdnspp/inproc/inproc_policy.h"
#include "mdnspp/inproc/inproc_socket.h"
#include "mdnspp/inproc/inproc_executor.h"

#include "mdnspp/policy.h"

#include "mdnspp/testing/test_clock.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <vector>
#include <system_error>

using mdnspp::inproc::inproc_bus;
using mdnspp::inproc::inproc_executor;
using mdnspp::inproc::inproc_socket;
using mdnspp::inproc::inproc_timer;
using mdnspp::testing::test_clock;
using Clock = test_clock;

static_assert(mdnspp::policy_like<mdnspp::inproc_test_policy>,
    "inproc_policy<test_clock> must satisfy policy_like concept");
static_assert(mdnspp::socket_like<mdnspp::inproc::inproc_socket<test_clock>>,
    "inproc_socket<test_clock> must satisfy socket_like concept");
static_assert(mdnspp::timer_like<mdnspp::inproc::inproc_timer<test_clock>>,
    "inproc_timer<test_clock> must satisfy timer_like concept");

namespace {

struct wait_record
{
    std::error_code ec;
    bool fired;
};

void arm(inproc_timer<Clock> &timer, std::chrono::milliseconds after, wait_record &rec)
{
    timer.expires_after(after);
    timer.async_wait([&rec](std::error_code ec)
    {
        rec.ec = ec;
        rec.fired = true;
    });
}

}

TEST_CASE("inproc_policy satisfies policy_like concept", "[inproc][conformance]")
{
    test_clock::reset();
    inproc_bus<Clock> bus;
    inproc_executor<Clock> ex{bus};

    inproc_socket<Clock> sock{ex};
    inproc_timer<Clock> timer{ex};

    REQUIRE_FALSE(bus.has_pending_packets());
    REQUIRE_FALSE(timer.has_pending());
}

TEST_CASE("inproc_timer fires on clock advance", "[inproc][timer]")
{
    test_clock::reset();
    inproc_bus<Clock> bus;
    inproc_executor<Clock> ex{bus};

    inproc_timer<Clock> timer{ex};

    wait_record rec{std::make_error_code(std::errc::interrupted), false};
    arm(timer, std::chrono::milliseconds{100}, rec);

    REQUIRE(timer.has_pending());

    test_clock::advance(std::chrono::milliseconds{50});
    ex.drain();
    REQUIRE_FALSE(rec.fired);

    test_clock::advance(std::chrono::milliseconds{50});
    ex.drain();

    REQUIRE(rec.fired);
    REQUIRE_FALSE(rec.ec);
}

TEST_CASE("inproc_timer cancel", "[inproc][timer]")
{
    test_clock::reset();
    inproc_bus<Clock> bus;
    inproc_executor<Clock> ex{bus};

    inproc_timer<Clock> timer{ex};

    wait_record rec{std::error_code{}, false};
    arm(timer, std::chrono::milliseconds{1000}, rec);

    REQUIRE(timer.has_pending());

    timer.cancel();

    REQUIRE_FALSE(timer.has_pending());
    REQUIRE(rec.fired);
    REQUIRE(rec.ec == std::make_error_code(std::errc::operation_canceled));
}

TEST_CASE("inproc_executor post and drain", "[inproc][executor]")
{
    test_clock::reset();
    inproc_bus<Clock> bus;
    inproc_executor<Clock> ex{bus};

    std::vector<int> order;

    mdnspp::inproc_test_policy::post(ex, [&] { order.push_back(1); });
    mdnspp::inproc_test_policy::post(ex, [&] { order.push_back(2); });
    mdnspp::inproc_test_policy::post(ex, [&] { order.push_back(3); });

    REQUIRE(order.empty());

    ex.drain();

    REQUIRE(order == std::vector<int>{1, 2, 3});
}
