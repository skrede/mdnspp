#ifndef HPP_GUARD_MDNSPP_TESTING_MOCK_TIMER_H
#define HPP_GUARD_MDNSPP_TESTING_MOCK_TIMER_H

#include "mdnspp/testing/mock_executor.h"

#include "mdnspp/detail/compat.h"

#include <chrono>
#include <cstdint>
#include <utility>
#include <system_error>

namespace mdnspp::testing {

class mock_timer
{
public:
    mock_timer()
        : m_pending_handler{}
        , m_last_duration{0}
        , m_cancel_count{0}
    {
    }

    explicit mock_timer(mock_executor &)
        : mock_timer()
    {
    }

    explicit mock_timer(mock_executor &, std::error_code &)
        : mock_timer()
    {
    }

    // expires_after and cancel complete a pending wait last, so its handler may re-arm or destroy the timer.
    void expires_after(std::chrono::milliseconds d)
    {
        auto h = std::exchange(m_pending_handler, nullptr);
        m_last_duration = d;
        m_cancel_count++;
        if(h)
            h(std::make_error_code(std::errc::operation_canceled));
    }

    void async_wait(detail::move_only_function<void(std::error_code)> handler)
    {
        m_pending_handler = std::move(handler);
    }

    void cancel()
    {
        auto h = std::exchange(m_pending_handler, nullptr);
        m_cancel_count++;
        if(h)
            h(std::make_error_code(std::errc::operation_canceled));
    }

    void fire()
    {
        if(m_pending_handler)
        {
            auto h = std::exchange(m_pending_handler, nullptr);
            h(std::error_code{});
        }
    }

    int32_t cancel_count() const { return m_cancel_count; }
    bool has_pending() const { return m_pending_handler != nullptr; }
    std::chrono::milliseconds last_duration() const { return m_last_duration; }

private:
    detail::move_only_function<void(std::error_code)> m_pending_handler;
    std::chrono::milliseconds m_last_duration;
    int32_t m_cancel_count;
};

}

#endif
