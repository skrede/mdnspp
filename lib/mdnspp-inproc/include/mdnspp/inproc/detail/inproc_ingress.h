#ifndef HPP_GUARD_MDNSPP_INPROC_DETAIL_INPROC_INGRESS_H
#define HPP_GUARD_MDNSPP_INPROC_DETAIL_INPROC_INGRESS_H

#include "mdnspp/detail/compat.h"

#include <deque>
#include <mutex>
#include <atomic>
#include <vector>
#include <utility>

// In mdnspp::detail rather than mdnspp::inproc::detail: a nested inproc::detail would shadow the
// detail::move_only_function lookups inside mdnspp::inproc.
namespace mdnspp::detail {

class inproc_ingress
{
public:
    inproc_ingress()
        : m_mutex()
        , m_has_pending{false}
        , m_pending()
    {
    }

    inproc_ingress(const inproc_ingress &) = delete;
    inproc_ingress &operator=(const inproc_ingress &) = delete;
    inproc_ingress(inproc_ingress &&) = delete;
    inproc_ingress &operator=(inproc_ingress &&) = delete;

    void push(move_only_function<void()> fn)
    {
        const std::lock_guard<std::mutex> lock(m_mutex);
        m_pending.push_back(std::move(fn));
        m_has_pending.store(true, std::memory_order_relaxed);
    }

    // The stepping thread reads the pending flag with one relaxed load and takes the lock only when it is set; the
    // flag is written only under the lock, which orders the callables themselves.
    void drain_into(std::deque<move_only_function<void()>> &queue)
    {
        if(!m_has_pending.load(std::memory_order_relaxed))
            return;
        const std::lock_guard<std::mutex> lock(m_mutex);
        for(move_only_function<void()> &fn : m_pending)
            queue.push_back(std::move(fn));
        m_pending.clear();
        m_has_pending.store(false, std::memory_order_relaxed);
    }

private:
    std::mutex m_mutex;
    std::atomic<bool> m_has_pending;
    std::vector<move_only_function<void()>> m_pending;
};

}

#endif
