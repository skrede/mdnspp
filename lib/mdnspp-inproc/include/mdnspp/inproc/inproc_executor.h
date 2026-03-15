#ifndef HPP_GUARD_MDNSPP_INPROC_INPROC_EXECUTOR_H
#define HPP_GUARD_MDNSPP_INPROC_INPROC_EXECUTOR_H

#include "mdnspp/detail/compat.h"

#include "mdnspp/inproc/inproc_bus.h"

#include <deque>
#include <vector>
#include <chrono>
#include <algorithm>
#include <thread>

namespace mdnspp::inproc {

template <typename Clock>
class inproc_timer;

template <typename Clock = std::chrono::steady_clock>
class inproc_executor
{
public:
    explicit inproc_executor(inproc_bus<Clock> &bus)
        : m_bus(bus)
    {
    }

    ~inproc_executor() = default;

    inproc_executor(const inproc_executor &) = delete;
    inproc_executor &operator=(const inproc_executor &) = delete;
    inproc_executor(inproc_executor &&) = delete;
    inproc_executor &operator=(inproc_executor &&) = delete;

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

    void register_timer(inproc_timer<Clock> *t)
    {
        if(std::find(m_timers.begin(), m_timers.end(), t) == m_timers.end())
            m_timers.push_back(t);
    }

    void deregister_timer(inproc_timer<Clock> *t) noexcept
    {
        std::erase(m_timers, t);
    }

    inproc_bus<Clock> &bus() noexcept { return m_bus; }

private:
    inproc_bus<Clock> &m_bus;
    std::deque<detail::move_only_function<void()>> m_posted;
    std::vector<inproc_timer<Clock> *> m_timers;
    bool m_stopped{false};
};

}

#endif
