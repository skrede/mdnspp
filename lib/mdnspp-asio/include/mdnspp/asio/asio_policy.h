#ifndef HPP_GUARD_MDNSPP_ASIO_ASIO_POLICY_H
#define HPP_GUARD_MDNSPP_ASIO_ASIO_POLICY_H

#include "mdnspp/policy.h"

#include "mdnspp/detail/compat.h"

#include "mdnspp/asio/asio_socket.h"
#include "mdnspp/asio/asio_timer.h"

namespace mdnspp {

// asio_policy: production policy backed by asio::io_context.
//
// executor_type is asio::io_context & — a reference type used only as a
// constructor argument forwarded to asio_socket and asio_timer. Neither type
// stores the reference; they store the executor internally (matching ASIO
// convention: asio::ip::tcp::socket takes io_context & but stores executor).
struct asio_policy
{
    using executor_type = asio::io_context&;
    using socket_type = asio_socket;
    using timer_type = asio_timer;

    static void post(executor_type ex, detail::move_only_function<void()> fn)
    {
        asio::post(ex, std::move(fn));
    }
};

}

static_assert(mdnspp::policy_like<mdnspp::asio_policy>, "asio_policy must satisfy Policy concept");

#endif
