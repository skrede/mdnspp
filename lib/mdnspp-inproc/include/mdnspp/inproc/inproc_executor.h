#ifndef HPP_GUARD_MDNSPP_INPROC_INPROC_EXECUTOR_H
#define HPP_GUARD_MDNSPP_INPROC_INPROC_EXECUTOR_H

#include "mdnspp/inproc/inproc_bus.h"

#include "mdnspp/inproc/detail/inproc_ingress.h"

#include "mdnspp/detail/compat.h"

#include <deque>
#include <atomic>
#include <chrono>
#include <thread>
#include <vector>
#include <algorithm>
#include <functional>

namespace mdnspp::inproc {

template <typename Clock>
class inproc_timer_base
{
public:
    virtual ~inproc_timer_base() = default;

    virtual bool try_fire(typename Clock::time_point now) = 0;
};

template <typename Clock = std::chrono::steady_clock>
class inproc_executor
{
public:
    explicit inproc_executor(inproc_bus<Clock> &bus)
        : m_bus(bus)
        , m_stopped{false}
        , m_ingress()
        , m_posted()
        , m_timers()
    {
    }

    ~inproc_executor() = default;

    inproc_executor(const inproc_executor &) = delete;
    inproc_executor &operator=(const inproc_executor &) = delete;
    inproc_executor(inproc_executor &&) = delete;
    inproc_executor &operator=(inproc_executor &&) = delete;

    void post(detail::move_only_function<void()> fn)
    {
        m_ingress.push(std::move(fn));
    }

    bool step()
    {
        m_ingress.drain_into(m_posted);
        if(!m_posted.empty())
        {
            auto fn = std::move(m_posted.front());
            m_posted.pop_front();
            fn();
            return true;
        }

        const auto now = Clock::now();
        for(inproc_timer_base<Clock> &t : m_timers)
        {
            if(t.try_fire(now))
                return true;
        }

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
        while(!m_stopped.load(std::memory_order_acquire))
        {
            drain();
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
    }

    void stop()
    {
        m_stopped.store(true, std::memory_order_release);
    }

    void register_timer(inproc_timer_base<Clock> &t)
    {
        if(std::ranges::none_of(m_timers, [&t](const inproc_timer_base<Clock> &e) { return &e == &t; }))
            m_timers.push_back(t);
    }

    void deregister_timer(inproc_timer_base<Clock> &t) noexcept
    {
        std::erase_if(m_timers, [&t](const inproc_timer_base<Clock> &e) { return &e == &t; });
    }

    inproc_bus<Clock> &bus() noexcept { return m_bus; }

private:
    inproc_bus<Clock> &m_bus;
    std::atomic<bool> m_stopped;
    detail::inproc_ingress m_ingress;
    std::deque<detail::move_only_function<void()>> m_posted;
    std::vector<std::reference_wrapper<inproc_timer_base<Clock>>> m_timers;
};

}

#endif
