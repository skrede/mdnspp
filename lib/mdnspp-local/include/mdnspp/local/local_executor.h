#ifndef HPP_GUARD_MDNSPP_LOCAL_LOCAL_EXECUTOR_H
#define HPP_GUARD_MDNSPP_LOCAL_LOCAL_EXECUTOR_H

#include "mdnspp/detail/compat.h"

#include "mdnspp/local/local_bus.h"

#include <deque>
#include <vector>
#include <chrono>
#include <algorithm>
#include <thread>

namespace mdnspp::local {

template <typename Clock>
class local_timer;

template <typename Clock = std::chrono::steady_clock>
class local_executor
{
public:
    explicit local_executor(local_bus<Clock> &bus)
        : m_bus(bus)
    {
    }

    ~local_executor() = default;

    local_executor(const local_executor &) = delete;
    local_executor &operator=(const local_executor &) = delete;
    local_executor(local_executor &&) = delete;
    local_executor &operator=(local_executor &&) = delete;

    void post(detail::move_only_function<void()> fn)
    {
        m_posted.push_back(std::move(fn));
    }

    bool step()
    {
        // Priority 1: posted callbacks
        if(!m_posted.empty())
        {
            auto fn = std::move(m_posted.front());
            m_posted.pop_front();
            fn();
            return true;
        }

        // Priority 2: expired timers
        const auto now = Clock::now();
        for(auto *t : m_timers)
        {
            if(t->try_fire(now))
                return true;
        }

        // Priority 3: packet delivery
        if(m_bus.deliver_one())
            return true;

        return false;
    }

    void drain()
    {
        while(step())
        {
        }
    }

    void run()
    {
        while(!m_stopped)
        {
            drain();
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
    }

    void stop()
    {
        m_stopped = true;
    }

    void register_timer(local_timer<Clock> *t)
    {
        if(std::find(m_timers.begin(), m_timers.end(), t) == m_timers.end())
            m_timers.push_back(t);
    }

    void deregister_timer(local_timer<Clock> *t) noexcept
    {
        std::erase(m_timers, t);
    }

    local_bus<Clock> &bus() noexcept { return m_bus; }

private:
    local_bus<Clock> &m_bus;
    std::deque<detail::move_only_function<void()>> m_posted;
    std::vector<local_timer<Clock> *> m_timers;
    bool m_stopped{false};
};

}

#endif
