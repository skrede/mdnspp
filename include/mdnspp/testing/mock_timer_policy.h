#ifndef HPP_GUARD_MDNSPP_TESTING_MOCK_TIMER_POLICY_H
#define HPP_GUARD_MDNSPP_TESTING_MOCK_TIMER_POLICY_H

#include "mdnspp/timer_policy.h"
#include <chrono>
#include <functional>
#include <system_error>
#include <utility>

namespace mdnspp::testing {

class MockTimerPolicy
{
public:
    // expires_after: cancel any pending wait and record the new duration
    void expires_after(std::chrono::milliseconds)
    {
        m_pending_handler = nullptr;
        m_cancel_count++;
    }

    void async_wait(std::function<void(std::error_code)> handler)
    {
        m_pending_handler = std::move(handler);
    }

    void cancel()
    {
        m_cancel_count++;
        if(m_pending_handler)
        {
            auto h = std::exchange(m_pending_handler, nullptr);
            h(std::make_error_code(std::errc::operation_canceled));
        }
    }

    // Test control: simulate the silence timeout expiring naturally
    void fire()
    {
        if(m_pending_handler)
        {
            auto h = std::exchange(m_pending_handler, nullptr);
            h(std::error_code{});
        }
    }

    int cancel_count() const { return m_cancel_count; }
    bool has_pending() const { return m_pending_handler != nullptr; }

private:
    std::function<void(std::error_code)> m_pending_handler;
    int m_cancel_count{0};
};

} // namespace mdnspp::testing

// Concept conformance verified at compile time
static_assert(mdnspp::TimerPolicy<mdnspp::testing::MockTimerPolicy>,
              "MockTimerPolicy must satisfy TimerPolicy");

#endif // HPP_GUARD_MDNSPP_TESTING_MOCK_TIMER_POLICY_H
