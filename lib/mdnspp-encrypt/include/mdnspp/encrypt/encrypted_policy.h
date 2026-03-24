#ifndef HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_POLICY_H
#define HPP_GUARD_MDNSPP_ENCRYPT_ENCRYPTED_POLICY_H

#include "mdnspp/policy.h"
#include "mdnspp/encrypt/encrypted_socket.h"
#include "mdnspp/encrypt/encrypt_socket_options.h"

#include "mdnspp/detail/compat.h"

namespace mdnspp {

template <Policy Inner>
struct encrypted_policy
{
    using executor_type       = typename Inner::executor_type;
    using socket_type         = encrypted_socket<typename Inner::socket_type>;
    using timer_type          = typename Inner::timer_type;
    using socket_options_type = encrypt_socket_options;

    static void post(executor_type ex, detail::move_only_function<void()> fn)
    {
        Inner::post(ex, std::move(fn));
    }
};

}

#endif
