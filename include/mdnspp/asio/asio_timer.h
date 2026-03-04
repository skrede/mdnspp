#pragma once
#include <asio.hpp>
#include "mdnspp/policy.h"
#include <chrono>
#include <functional>
#include <system_error>

namespace mdnspp {

class AsioTimer
{
public:
    explicit AsioTimer(asio::io_context &io)
        : m_timer(io)
    {
    }

    explicit AsioTimer(asio::io_context &io, std::error_code &)
        : m_timer(io)
    {
        // Timer construction is infallible; error_code left unchanged.
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

}

static_assert(mdnspp::TimerLike<mdnspp::AsioTimer>, "AsioTimer must satisfy TimerLike — check expires_after/async_wait/cancel signatures"
);
