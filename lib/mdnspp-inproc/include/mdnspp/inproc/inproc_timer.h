#ifndef HPP_GUARD_MDNSPP_INPROC_INPROC_TIMER_H
#define HPP_GUARD_MDNSPP_INPROC_INPROC_TIMER_H

#include "mdnspp/detail/compat.h"
#include "mdnspp/inproc/inproc_executor.h"

#include <chrono>
#include <system_error>

namespace mdnspp::inproc {

template <typename Clock = std::chrono::steady_clock>
class inproc_timer
{
public:
    explicit inproc_timer(inproc_executor<Clock> &ex)
        : m_exec(&ex)
    {
        m_exec->register_timer(this);
    }

    explicit inproc_timer(inproc_executor<Clock> &ex, std::error_code &)
        : m_exec(&ex)
    {
        m_exec->register_timer(this);
    }

    ~inproc_timer()
    {
        if(m_exec)
            m_exec->deregister_timer(this);
    }

    inproc_timer(const inproc_timer &) = delete;
    inproc_timer &operator=(const inproc_timer &) = delete;
    inproc_timer(inproc_timer &&) = delete;
    inproc_timer &operator=(inproc_timer &&) = delete;

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

    void async_wait(detail::move_only_function<void(std::error_code)> handler)
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
    inproc_executor<Clock> *m_exec;
    typename Clock::time_point m_expiry{};
    detail::move_only_function<void(std::error_code)> m_handler;
    bool m_active{false};
    int m_cancel_count{0};
};

}

#endif
