#ifndef HPP_GUARD_MDNSPP_INPROC_INPROC_POLICY_H
#define HPP_GUARD_MDNSPP_INPROC_INPROC_POLICY_H

#include "mdnspp/policy.h"
#include "mdnspp/detail/compat.h"
#include "mdnspp/testing/test_clock.h"

#include "mdnspp/inproc/inproc_bus.h"
#include "mdnspp/inproc/inproc_timer.h"
#include "mdnspp/inproc/inproc_socket.h"
#include "mdnspp/inproc/inproc_executor.h"

#include <chrono>

namespace mdnspp::inproc {

template <typename Clock = std::chrono::steady_clock>
struct inproc_policy
{
    using executor_type = inproc_executor<Clock> &;
    using socket_type = inproc_socket<Clock>;
    using timer_type = inproc_timer<Clock>;

    static void post(executor_type ex, detail::move_only_function<void()> fn)
    {
        ex.post(std::move(fn));
    }
};

}

namespace mdnspp {

using InProcPolicy = inproc::inproc_policy<std::chrono::steady_clock>;
using InProcTestPolicy = inproc::inproc_policy<testing::test_clock>;

}

static_assert(mdnspp::Policy<mdnspp::InProcTestPolicy>,
    "inproc_policy<test_clock> must satisfy Policy — check socket/timer constructors");

#endif
