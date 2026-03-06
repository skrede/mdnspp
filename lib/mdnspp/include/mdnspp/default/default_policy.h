#ifndef HPP_GUARD_MDNSPP_DEFAULT_POLICY_H
#define HPP_GUARD_MDNSPP_DEFAULT_POLICY_H

// DefaultPolicy — traits struct bundling NativeContext + NativeSocket + NativeTimer.
// Satisfies Policy<P>: executor_type, socket_type, timer_type all present with
// the required constructors (throwing and error_code overloads).

#include "mdnspp/policy.h"
#include "mdnspp/detail/compat.h"

#include "mdnspp/default/default_timer.h"
#include "mdnspp/default/default_socket.h"
#include "mdnspp/default/default_context.h"

namespace mdnspp {

struct DefaultPolicy
{
    using executor_type = DefaultContext&;
    using socket_type = DefaultSocket;
    using timer_type = DefaultTimer;

    static void post(executor_type ex, detail::move_only_function<void()> fn)
    {
        ex.post(std::move(fn));
    }
};

}

static_assert(mdnspp::Policy<mdnspp::DefaultPolicy>, "DefaultPolicy must satisfy Policy — check DefaultSocket/DefaultTimer constructor signatures");

#endif
