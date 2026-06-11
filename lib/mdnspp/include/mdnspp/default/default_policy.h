#ifndef HPP_GUARD_MDNSPP_DEFAULT_DEFAULT_POLICY_H
#define HPP_GUARD_MDNSPP_DEFAULT_DEFAULT_POLICY_H

// default_policy — traits struct bundling default_context + default_socket + default_timer.
// Satisfies policy_like<P>: executor_type, socket_type, timer_type all present with
// the required constructors (throwing and error_code overloads).

#include "mdnspp/policy.h"
#include "mdnspp/detail/compat.h"

#include "mdnspp/default/default_timer.h"
#include "mdnspp/default/default_socket.h"
#include "mdnspp/default/default_context.h"

namespace mdnspp {

struct default_policy
{
    using executor_type = default_context&;
    using socket_type = default_socket;
    using timer_type = default_timer;

    static void post(executor_type ex, detail::move_only_function<void()> fn)
    {
        ex.post(std::move(fn));
    }
};

}

static_assert(mdnspp::policy_like<mdnspp::default_policy>, "default_policy must satisfy Policy — check default_socket/default_timer constructor signatures");

#endif


