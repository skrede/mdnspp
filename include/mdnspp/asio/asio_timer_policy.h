#pragma once
#include <asio.hpp>
#include "mdnspp/timer_policy.h"
#include <chrono>
#include <functional>
#include <system_error>

namespace mdnspp::asio_policy {

class AsioTimerPolicy
{
public:
    explicit AsioTimerPolicy(asio::io_context &io)
        : m_timer(io)
    {
    }

    void expires_after(std::chrono::milliseconds dur)
    {
        m_timer.expires_after(dur);
    }

    void async_wait(std::function<void(std::error_code)> handler)
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

} // namespace mdnspp::asio_policy

static_assert(
    mdnspp::TimerPolicy<mdnspp::asio_policy::AsioTimerPolicy>,
    "AsioTimerPolicy must satisfy TimerPolicy — check expires_after/async_wait/cancel signatures"
);
