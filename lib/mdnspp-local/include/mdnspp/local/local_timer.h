#ifndef HPP_GUARD_MDNSPP_LOCAL_LOCAL_TIMER_H
#define HPP_GUARD_MDNSPP_LOCAL_LOCAL_TIMER_H

#include "mdnspp/local/local_executor.h"

#include <chrono>
#include <functional>
#include <system_error>

namespace mdnspp::local {

template <typename Clock = std::chrono::steady_clock>
class local_timer
{
public:
    explicit local_timer(local_executor<Clock> &ex)
        : m_exec(&ex)
    {
        m_exec->register_timer(this);
    }

    explicit local_timer(local_executor<Clock> &ex, std::error_code &)
        : m_exec(&ex)
    {
        m_exec->register_timer(this);
    }

    ~local_timer()
    {
        if(m_exec)
            m_exec->deregister_timer(this);
    }

    local_timer(const local_timer &) = delete;
    local_timer &operator=(const local_timer &) = delete;
    local_timer(local_timer &&) = delete;
    local_timer &operator=(local_timer &&) = delete;

    void expires_after(std::chrono::milliseconds d)
    {
        m_expiry = Clock::now() + d;
        // Cancel any pending handler
        if(m_handler)
        {
            auto h = std::exchange(m_handler, nullptr);
            h(std::make_error_code(std::errc::operation_canceled));
        }
        m_active = true;
    }

    void async_wait(std::function<void(std::error_code)> handler)
    {
        m_handler = std::move(handler);
    }

    void cancel()
    {
        ++m_cancel_count;
        m_active = false;
        if(m_handler)
        {
            auto h = std::exchange(m_handler, nullptr);
            h(std::make_error_code(std::errc::operation_canceled));
        }
    }

    bool try_fire(typename Clock::time_point now)
    {
        if(!m_active || !m_handler)
            return false;
        if(now < m_expiry)
            return false;

        m_active = false;
        auto h = std::exchange(m_handler, nullptr);
        h(std::error_code{});
        return true;
    }

    [[nodiscard]] bool has_pending() const noexcept { return m_handler != nullptr; }
    [[nodiscard]] typename Clock::time_point expiry() const noexcept { return m_expiry; }

private:
    local_executor<Clock> *m_exec;
    typename Clock::time_point m_expiry{};
    std::function<void(std::error_code)> m_handler;
    bool m_active{false};
    int m_cancel_count{0};
};

}

#endif
