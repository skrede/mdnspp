#ifndef HPP_GUARD_MDNSPP_DETAIL_POLICY_CLOCK_H
#define HPP_GUARD_MDNSPP_DETAIL_POLICY_CLOCK_H

#include <chrono>

namespace mdnspp::detail {

template <typename P>
struct policy_clock
{
    using type = std::chrono::steady_clock;
};

template <typename P>
    requires requires { typename P::clock_type; }
struct policy_clock<P>
{
    using type = typename P::clock_type;
};

template <typename P>
using policy_clock_t = typename policy_clock<P>::type;

}

#endif
