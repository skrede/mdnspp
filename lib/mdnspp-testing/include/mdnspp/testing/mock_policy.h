#ifndef HPP_GUARD_MDNSPP_TESTING_MOCK_POLICY_H
#define HPP_GUARD_MDNSPP_TESTING_MOCK_POLICY_H

#include "mdnspp/testing/mock_timer.h"
#include "mdnspp/testing/mock_socket.h"
#include "mdnspp/testing/mock_executor.h"

#include "mdnspp/policy.h"

#include "mdnspp/detail/compat.h"

#include <utility>

namespace mdnspp::testing {

struct mock_policy
{
    using executor_type = mock_executor &;
    using socket_type = mock_socket;
    using timer_type = mock_timer;

    static void post(executor_type ex, detail::move_only_function<void()> fn)
    {
        ex.m_posted.push_back(std::move(fn));
    }
};

}

static_assert(mdnspp::policy_like<mdnspp::testing::mock_policy>, "mock_policy must satisfy Policy concept");

#endif
