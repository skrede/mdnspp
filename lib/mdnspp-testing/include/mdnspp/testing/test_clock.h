#ifndef HPP_GUARD_MDNSPP_TESTING_TEST_CLOCK_H
#define HPP_GUARD_MDNSPP_TESTING_TEST_CLOCK_H

#include <chrono>

namespace mdnspp::testing {

struct test_clock
{
    using rep = std::chrono::steady_clock::rep;
    using period = std::chrono::steady_clock::period;
    using duration = std::chrono::steady_clock::duration;
    using time_point = std::chrono::time_point<test_clock, duration>;
    static constexpr bool is_steady = true;

    static time_point now() noexcept { return s_now; }
    static void advance(duration d) noexcept { s_now += d; }
    static void reset() noexcept { s_now = time_point{}; }

    static inline time_point s_now{};
};

}

#endif
