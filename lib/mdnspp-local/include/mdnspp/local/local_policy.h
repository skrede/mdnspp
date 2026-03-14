#ifndef HPP_GUARD_MDNSPP_LOCAL_LOCAL_POLICY_H
#define HPP_GUARD_MDNSPP_LOCAL_LOCAL_POLICY_H

#include "mdnspp/policy.h"
#include "mdnspp/detail/compat.h"
#include "mdnspp/testing/test_clock.h"

#include "mdnspp/local/local_bus.h"
#include "mdnspp/local/local_timer.h"
#include "mdnspp/local/local_socket.h"
#include "mdnspp/local/local_executor.h"

#include <chrono>

namespace mdnspp::local {

template <typename Clock = std::chrono::steady_clock>
struct local_policy
{
    using executor_type = local_executor<Clock> &;
    using socket_type = local_socket<Clock>;
    using timer_type = local_timer<Clock>;

    static void post(executor_type ex, detail::move_only_function<void()> fn)
    {
        ex.post(std::move(fn));
    }
};

}

namespace mdnspp {

using LocalPolicy = local::local_policy<std::chrono::steady_clock>;
using LocalTestPolicy = local::local_policy<testing::test_clock>;

}

static_assert(mdnspp::Policy<mdnspp::LocalTestPolicy>,
    "local_policy<test_clock> must satisfy Policy — check socket/timer constructors");

#endif
