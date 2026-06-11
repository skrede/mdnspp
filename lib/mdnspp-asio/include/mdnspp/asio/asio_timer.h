#ifndef HPP_GUARD_MDNSPP_ASIO_ASIO_TIMER_H
#define HPP_GUARD_MDNSPP_ASIO_ASIO_TIMER_H

#include "mdnspp/policy.h"

#include "mdnspp/detail/compat.h"

#include <asio.hpp>

#include <chrono>
#include <system_error>

namespace mdnspp {

class asio_timer
{
public:
    explicit asio_timer(asio::io_context &io)
        : m_timer(io)
    {
    }

    explicit asio_timer(asio::io_context &io, std::error_code &)
        : m_timer(io)
    {
    }

    void expires_after(std::chrono::milliseconds dur)
    {
        m_timer.expires_after(dur);
    }

    void async_wait(detail::move_only_function<void(std::error_code)> handler)
    {
        m_timer.async_wait(std::move(handler));
    }

    void cancel()
    {
        m_timer.cancel();
    }

private:
    asio::steady_timer m_timer;
};

}

static_assert(mdnspp::timer_like<mdnspp::asio_timer>, "asio_timer must satisfy timer_like — check expires_after/async_wait/cancel signatures");

#endif
