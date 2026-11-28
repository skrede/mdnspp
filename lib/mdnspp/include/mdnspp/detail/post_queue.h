#ifndef HPP_GUARD_MDNSPP_DETAIL_POST_QUEUE_H
#define HPP_GUARD_MDNSPP_DETAIL_POST_QUEUE_H

#include "mdnspp/detail/compat.h"

#include <deque>
#include <mutex>
#include <cstddef>
#include <utility>
#include <iterator>

namespace mdnspp::detail {

struct no_post_hooks
{
    template <typename Queue>
    void after_swap(Queue &) noexcept
    {
    }
};

template <typename Hooks = no_post_hooks>
class post_queue
{
public:
    explicit post_queue(move_only_function<void()> wake_cb, Hooks hooks = {})
        : m_pending{false}
        , m_hooks{std::move(hooks)}
        , m_wake_cb{std::move(wake_cb)}
    {
    }

    void post(move_only_function<void()> fn)
    {
        bool need_wake = false;
        {
            std::lock_guard lock{m_mutex};
            m_queue.push_back(std::move(fn));
            need_wake = !std::exchange(m_pending, true);
        }
        if(need_wake)
            m_wake_cb();
    }

    std::size_t drain()
    {
        std::deque<move_only_function<void()>> taken = take_all();
        m_hooks.after_swap(*this);
        std::size_t ran = 0;
        try
        {
            for(; !taken.empty(); ++ran)
            {
                move_only_function<void()> fn = std::move(taken.front());
                taken.pop_front();
                fn();
            }
        }
        catch(...)
        {
            requeue_front(taken);
            throw;
        }
        return ran;
    }

    void clear()
    {
        take_all();
    }

    bool pending() const
    {
        std::lock_guard lock{m_mutex};
        return m_pending;
    }

private:
    mutable std::mutex m_mutex;
    std::deque<move_only_function<void()>> m_queue;
    bool m_pending;
    Hooks m_hooks;
    move_only_function<void()> m_wake_cb;

    std::deque<move_only_function<void()>> take_all()
    {
        std::deque<move_only_function<void()>> taken;
        std::lock_guard lock{m_mutex};
        taken.swap(m_queue);
        m_pending = false;
        return taken;
    }

    void requeue_front(std::deque<move_only_function<void()>> &rest)
    {
        bool need_wake = false;
        {
            std::lock_guard lock{m_mutex};
            m_queue.insert(m_queue.begin(), std::make_move_iterator(rest.begin()), std::make_move_iterator(rest.end()));
            need_wake = !std::exchange(m_pending, true);
        }
        if(need_wake)
            m_wake_cb();
    }
};

}

#endif
